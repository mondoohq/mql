// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlLuksVolumeInternal struct {
	dump   luksDump
	parsed bool
}

func (l *mqlLuks) id() (string, error) {
	return "luks", nil
}

// validDevicePath restricts the device strings we'll forward to
// `cryptsetup luksDump`. lsblk's `--paths` output yields canonical
// `/dev/...` paths and the kernel naming scheme allows only letters,
// digits, dashes, underscores, slashes, and the bracket characters
// LVM/dm uses (e.g. `/dev/mapper/vg-lv`, `/dev/disk/by-uuid/...`).
// Rejecting anything outside that alphabet keeps shell metacharacters
// out of the command line even if the kernel ever returns an
// unexpected name.
var validDevicePath = regexp.MustCompile(`^/dev/[A-Za-z0-9._/=:+@-]+$`)

func (l *mqlLuks) volumes() ([]any, error) {
	// Run lsblk ourselves instead of reusing the `lsblk` resource:
	// `cryptsetup luksDump` needs a device path, and only `--paths`
	// yields the canonical `/dev/...` form.
	o, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("lsblk --json --fs --paths"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	stdout, err := commandOutput(cmd, "lsblk")
	if err != nil {
		return nil, err
	}

	parsed, err := parseBlockEntries([]byte(stdout))
	if err != nil {
		return nil, err
	}

	devices := collectLuksDevices(parsed.Blockdevices)

	volumes := []any{}
	for _, dev := range devices {
		if !validDevicePath.MatchString(dev.Name) {
			log.Warn().Str("device", dev.Name).Msg("luks: rejecting device with unexpected name")
			continue
		}

		dump, err := runLuksDump(l.MqlRuntime, dev.Name)
		if err != nil {
			log.Debug().Err(err).Str("device", dev.Name).Msg("luks: skipping device")
			continue
		}

		vol, err := newLuksVolume(l.MqlRuntime, dev.Name, dump)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, vol)
	}
	return volumes, nil
}

// collectLuksDevices walks the lsblk tree depth-first and returns every
// device with fstype == "crypto_LUKS", at any depth. This covers
// LUKS-on-partition (the common case), LUKS-on-whole-disk, and
// LUKS-on-LVM topologies.
func collectLuksDevices(devs []blockdevice) []blockdevice {
	var out []blockdevice
	var walk func([]blockdevice)
	walk = func(devs []blockdevice) {
		for _, d := range devs {
			if isLuksFstype(d.Fstype) {
				out = append(out, d)
			}
			walk(d.Children)
		}
	}
	walk(devs)
	return out
}

func runLuksDump(runtime *plugin.Runtime, device string) (luksDump, error) {
	// device has already been validated against validDevicePath. The %q
	// quoting is belt-and-braces in case the command resource shells
	// out — it survives both shell-eval and exec-style invocation.
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(fmt.Sprintf("cryptsetup luksDump %q", device)),
	})
	if err != nil {
		return luksDump{}, err
	}
	cmd := o.(*mqlCommand)
	stdout, err := commandOutput(cmd, "cryptsetup luksDump")
	if err != nil {
		return luksDump{}, err
	}
	return parseLuksDump(stdout)
}

func newLuksVolume(runtime *plugin.Runtime, device string, dump luksDump) (*mqlLuksVolume, error) {
	res, err := CreateResource(runtime, "luks.volume", map[string]*llx.RawData{
		"name":          llx.StringData(device),
		"uuid":          llx.StringData(dump.UUID),
		"version":       llx.IntData(int64(dump.Version)),
		"label":         llx.StringData(dump.Label),
		"subsystem":     llx.StringData(dump.Subsystem),
		"masterKeyBits": llx.IntData(int64(dump.MasterKeyBits)),
		"payloadOffset": llx.IntData(int64(dump.PayloadOffset)),
		"tokens":        llx.ArrayData(luksTokensToDicts(dump.Tokens), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	vol := res.(*mqlLuksVolume)
	vol.dump = dump
	vol.parsed = true
	return vol, nil
}

// luksTokensToDicts converts parsed token maps to llx-compatible dict
// values. The parser stores keyslot indices as []int64; llx dicts
// expect []any for nested arrays. A fresh map is returned per token so
// the caller's input is not mutated.
func luksTokensToDicts(tokens []map[string]any) []any {
	out := make([]any, 0, len(tokens))
	for _, t := range tokens {
		normalized := make(map[string]any, len(t))
		for k, v := range t {
			if slice, ok := v.([]int64); ok {
				asAny := make([]any, len(slice))
				for i, n := range slice {
					asAny[i] = n
				}
				normalized[k] = asAny
				continue
			}
			normalized[k] = v
		}
		out = append(out, normalized)
	}
	return out
}

func (v *mqlLuksVolume) id() (string, error) {
	if v.Uuid.Data == "" {
		return "", errors.New("luks.volume: uuid is required for the resource id")
	}
	return v.Uuid.Data, nil
}

func (v *mqlLuksVolume) blockDevice() (*mqlLsblkEntry, error) {
	// Best-effort lookup against the `lsblk` resource. For LUKS volumes
	// that don't appear in its list, we report a null reference rather
	// than fabricating one.
	lsblkRes, err := CreateResource(v.MqlRuntime, "lsblk", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := lsblkRes.(*mqlLsblk).GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, raw := range list.Data {
		entry := raw.(*mqlLsblkEntry)
		if entry.Name.Data == v.Name.Data {
			return entry, nil
		}
	}
	v.BlockDevice.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (v *mqlLuksVolume) cipher() (*mqlLuksVolumeCipher, error) {
	if !v.parsed {
		return nil, errors.New("luks volume dump not available")
	}
	c := v.dump.Cipher
	res, err := CreateResource(v.MqlRuntime, "luks.volume.cipher", map[string]*llx.RawData{
		"__id":    llx.StringData(v.Uuid.Data + "/cipher"),
		"name":    llx.StringData(c.Name),
		"mode":    llx.StringData(c.Mode),
		"spec":    llx.StringData(c.Spec),
		"keySize": llx.IntData(int64(c.KeySize)),
		"hash":    llx.StringData(c.Hash),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlLuksVolumeCipher), nil
}

func (v *mqlLuksVolume) keyslots() ([]any, error) {
	if !v.parsed {
		return nil, errors.New("luks volume dump not available")
	}
	out := make([]any, 0, len(v.dump.Keyslots))
	for _, k := range v.dump.Keyslots {
		res, err := CreateResource(v.MqlRuntime, "luks.keyslot", map[string]*llx.RawData{
			"__id":              llx.StringData(fmt.Sprintf("%s/keyslot/%d", v.Uuid.Data, k.Index)),
			"index":             llx.IntData(int64(k.Index)),
			"state":             llx.StringData(k.State),
			"kdf":               llx.StringData(k.KDF),
			"iterations":        llx.IntData(int64(k.Iterations)),
			"time":              llx.IntData(int64(k.Time)),
			"memory":            llx.IntData(int64(k.Memory)),
			"parallel":          llx.IntData(int64(k.Parallel)),
			"hash":              llx.StringData(k.Hash),
			"stripes":           llx.IntData(int64(k.Stripes)),
			"keyMaterialOffset": llx.IntData(int64(k.KeyMaterialOffset)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
