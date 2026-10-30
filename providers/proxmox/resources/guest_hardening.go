// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// hotplugDefaults is what Proxmox applies when a VM config carries no
// `hotplug` line, and what the `1` shorthand expands to. Reporting it is
// reporting what the hypervisor does: a VM nobody configured still accepts a
// USB device or a disk attached to it while it runs.
var hotplugDefaults = []string{"network", "disk", "usb"}

// ---------------------------------------------------------------------------
// Raw config access that does not hide a failed read
// ---------------------------------------------------------------------------

// cfgRaw reads one key out of the VM config, keeping three outcomes apart: the
// key is set, the key is absent, or the config could not be read at all.
//
// The last one matters most. A field that reported "no vTPM attached" because
// the config fetch was denied would be a posture claim about a VM nobody read,
// so the error is returned and the field surfaces as an error rather than as a
// confident negative.
func (r *mqlProxmoxVm) cfgRaw(key string) (string, bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return "", false, r.configErr
	}
	v, ok := r.vmConfig[key]
	if !ok || v == nil {
		return "", false, nil
	}
	return fmt.Sprintf("%v", v), true, nil
}

// cfgProps parses one VM config line as a property string. found is false when
// the key is absent, which is how the accessors below tell "the device is not
// attached" from "the device is attached with this setting left at its
// default".
func (r *mqlProxmoxVm) cfgProps(key, defaultKey string) (map[string]string, bool, error) {
	raw, found, err := r.cfgRaw(key)
	if err != nil || !found {
		return nil, false, err
	}
	return connection.ParsePropertyString(raw, defaultKey), true, nil
}

func (r *mqlProxmoxContainer) cfgRaw(key string) (string, bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return "", false, r.configErr
	}
	v, ok := r.ctConfig[key]
	if !ok || v == nil {
		return "", false, nil
	}
	return fmt.Sprintf("%v", v), true, nil
}

// ---------------------------------------------------------------------------
// VM boot integrity: EFI vars disk and virtual TPM
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVm) efiType() (string, error) {
	props, found, err := r.cfgProps("efidisk0", "file")
	if err != nil {
		return "", err
	}
	if !found {
		r.EfiType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if t := props["efitype"]; t != "" {
		return t, nil
	}
	// Proxmox documents 2m as the fallback for EFI vars disks created before
	// 4m existed, so an unset efitype genuinely means the guest gets 2m.
	return "2m", nil
}

func (r *mqlProxmoxVm) preEnrolledKeys() (bool, error) {
	props, found, err := r.cfgProps("efidisk0", "file")
	if err != nil {
		return false, err
	}
	if !found {
		// No EFI vars disk means there is no key store to have enrolled
		// anything into, which is a different fact from an empty one.
		r.PreEnrolledKeys.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if v := connection.PropBool(props, "pre-enrolled-keys"); v != nil {
		return *v, nil
	}
	return false, nil
}

func (r *mqlProxmoxVm) vtpmPresent() (bool, error) {
	_, found, err := r.cfgRaw("tpmstate0")
	if err != nil {
		return false, err
	}
	return found, nil
}

func (r *mqlProxmoxVm) vtpmVersion() (string, error) {
	props, found, err := r.cfgProps("tpmstate0", "file")
	if err != nil {
		return "", err
	}
	if !found {
		r.VtpmVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if v := props["version"]; v != "" {
		return v, nil
	}
	return "v1.2", nil
}

// ---------------------------------------------------------------------------
// VM memory encryption: AMD SEV
// ---------------------------------------------------------------------------

// sevProps reads the `amd-sev` line. Every SEV sub-setting is null when the
// line is absent: a VM that does not use SEV has no SEV debugging policy to
// report, and answering false would claim the weaker of the two states about a
// feature that is not in play at all.
func (r *mqlProxmoxVm) sevProps() (map[string]string, bool, error) {
	return r.cfgProps("amd-sev", "type")
}

func (r *mqlProxmoxVm) sevType() (string, error) {
	props, found, err := r.sevProps()
	if err != nil {
		return "", err
	}
	if !found {
		r.SevType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return props["type"], nil
}

func (r *mqlProxmoxVm) sevFlag(key string, slot *plugin.TValue[bool]) (bool, error) {
	props, found, err := r.sevProps()
	if err != nil {
		return false, err
	}
	if !found {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if v := connection.PropBool(props, key); v != nil {
		return *v, nil
	}
	return false, nil
}

func (r *mqlProxmoxVm) sevNoDebug() (bool, error) {
	return r.sevFlag("no-debug", &r.SevNoDebug)
}

func (r *mqlProxmoxVm) sevNoKeySharing() (bool, error) {
	return r.sevFlag("no-key-sharing", &r.SevNoKeySharing)
}

func (r *mqlProxmoxVm) sevKernelHashes() (bool, error) {
	return r.sevFlag("kernel-hashes", &r.SevKernelHashes)
}

// ---------------------------------------------------------------------------
// VM CPU exposure
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVm) cpuType() (string, error) {
	props, _, err := r.cfgProps("cpu", "cputype")
	if err != nil {
		return "", err
	}
	return props["cputype"], nil
}

func (r *mqlProxmoxVm) cpuFlags() ([]any, error) {
	props, _, err := r.cfgProps("cpu", "cputype")
	if err != nil {
		return nil, err
	}
	return splitCPUFlags(props["flags"]), nil
}

// splitCPUFlags splits the `flags=` value of a `cpu` config line. Proxmox
// separates the individual flags with semicolons, not commas, precisely so the
// list survives inside a comma-delimited property string. Each flag keeps its
// leading sign, since `+spec-ctrl` and `-spec-ctrl` are opposite answers to
// the same audit question.
func splitCPUFlags(raw string) []any {
	out := []any{}
	for _, flag := range strings.Split(raw, ";") {
		flag = strings.TrimSpace(flag)
		if flag == "" {
			continue
		}
		out = append(out, flag)
	}
	return out
}

func (r *mqlProxmoxVm) cpuHidden() (bool, error) {
	props, _, err := r.cfgProps("cpu", "cputype")
	if err != nil {
		return false, err
	}
	if v := connection.PropBool(props, "hidden"); v != nil {
		return *v, nil
	}
	return false, nil
}

func (r *mqlProxmoxVm) kvmEnabled() (bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return false, r.configErr
	}
	if v := connection.ConfigBool(r.vmConfig, "kvm"); v != nil {
		return *v, nil
	}
	// Proxmox enables KVM unless told otherwise, so an absent key means the
	// guest really is hardware-accelerated.
	return true, nil
}

// ---------------------------------------------------------------------------
// VM hotplug surface and entropy source
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVm) hotplugFeatures() ([]any, error) {
	raw, found, err := r.cfgRaw("hotplug")
	if err != nil {
		return nil, err
	}
	return parseHotplugFeatures(raw, found), nil
}

// parseHotplugFeatures turns the `hotplug` config value into the device
// classes that can be attached to the running guest.
//
// Absent and `1` both mean the Proxmox default set, and `0` is the only value
// that means nothing may be hotplugged. Returning an empty list for an absent
// key would report the opposite of what the hypervisor allows.
func parseHotplugFeatures(raw string, found bool) []any {
	raw = strings.TrimSpace(raw)
	if !found || raw == "" || raw == "1" {
		return stringsToAny(hotplugDefaults)
	}
	if raw == "0" {
		return []any{}
	}
	out := []any{}
	for _, feature := range strings.Split(raw, ",") {
		feature = strings.TrimSpace(feature)
		if feature == "" {
			continue
		}
		out = append(out, feature)
	}
	return out
}

func (r *mqlProxmoxVm) rngSource() (string, error) {
	props, found, err := r.cfgProps("rng0", "source")
	if err != nil {
		return "", err
	}
	if !found {
		r.RngSource.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return props["source"], nil
}

func (r *mqlProxmoxVm) rngMaxBytes() (int64, error) {
	props, found, err := r.cfgProps("rng0", "source")
	if err != nil {
		return 0, err
	}
	raw, ok := "", false
	if found {
		raw, ok = props["max_bytes"]
	}
	if !ok {
		r.RngMaxBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		// A limiter the API returned in a shape we cannot read is not a
		// limiter of zero, which would mean unlimited.
		r.RngMaxBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Container hook script and console
// ---------------------------------------------------------------------------

func (r *mqlProxmoxContainer) hookscript() (string, error) {
	raw, _, err := r.cfgRaw("hookscript")
	return raw, err
}

func (r *mqlProxmoxContainer) debug() (bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return false, r.configErr
	}
	if v := connection.ConfigBool(r.ctConfig, "debug"); v != nil {
		return *v, nil
	}
	return false, nil
}

func (r *mqlProxmoxContainer) consoleEnabled() (bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return false, r.configErr
	}
	if v := connection.ConfigBool(r.ctConfig, "console"); v != nil {
		return *v, nil
	}
	// Proxmox attaches /dev/console unless told otherwise.
	return true, nil
}
