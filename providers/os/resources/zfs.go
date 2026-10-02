// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/zfs"
	"go.mondoo.com/mql/types"
)

// validZfsName matches valid ZFS pool, dataset, and snapshot names.
// ZFS names consist of alphanumerics, underscores, hyphens, periods, colons, and slashes.
// Snapshot names include an @ separator.
var validZfsName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]*$`)

type mqlZfsInternal struct {
	lock sync.Mutex
	// noJSON is set once a zfs or zpool command rejected the -j flag
	noJSON bool
}

func (z *mqlZfs) id() (string, error) {
	return "zfs", nil
}

// runZfsCommand runs a zfs or zpool command and returns its stdout. A non-zero
// exit code is returned as an error with the given description. A tool that is
// not on the PATH is looked up in /usr/sbin and /sbin (see runSbinCommand).
func runZfsCommand(runtime *plugin.Runtime, command string, what string) (string, string, error) {
	cmd, err := runSbinCommand(runtime, command)
	if err != nil {
		return "", "", err
	}
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return "", "", exit.Error
	} else if exit.Data != 0 {
		return "", cmd.Stderr.Data, errors.New("could not retrieve " + what + ": " + cmd.Stderr.Data)
	}
	return cmd.Stdout.Data, "", nil
}

// zfsOutput is the output of a zfs or zpool command, either from its JSON form
// or from its text form.
type zfsOutput struct {
	json string
	text []string
}

func (o zfsOutput) isJSON() bool {
	return o.text == nil
}

// runZfsJSONOrText runs jsonCmd, which asks zfs or zpool for JSON output (-j).
// OpenZFS added -j in 2.3; older releases (FreeBSD 13 and 14, Ubuntu 22.04 and
// 24.04, Debian 12) reject it. Then the textCmds are run instead, and every
// later call skips the JSON attempt.
func runZfsJSONOrText(runtime *plugin.Runtime, what string, jsonCmd string, textCmds ...string) (zfsOutput, error) {
	obj, err := CreateResource(runtime, "zfs", map[string]*llx.RawData{})
	if err != nil {
		return zfsOutput{}, err
	}
	z := obj.(*mqlZfs)

	z.lock.Lock()
	noJSON := z.noJSON
	z.lock.Unlock()

	if !noJSON {
		out, stderr, err := runZfsCommand(runtime, jsonCmd, what)
		if err == nil {
			return zfsOutput{json: out}, nil
		}
		if !zfs.IsJSONUnsupported(stderr) {
			return zfsOutput{}, err
		}
		z.lock.Lock()
		z.noJSON = true
		z.lock.Unlock()
	}

	text := make([]string, 0, len(textCmds))
	for _, c := range textCmds {
		out, _, err := runZfsCommand(runtime, c, what)
		if err != nil {
			return zfsOutput{}, err
		}
		text = append(text, out)
	}
	return zfsOutput{text: text}, nil
}

func (z *mqlZfs) version() (string, error) {
	cmd, err := runSbinCommand(z.MqlRuntime, "zfs version")
	if err != nil {
		return "", err
	}
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return "", exit.Error
	} else if exit.Data != 0 {
		if strings.Contains(cmd.Stderr.Data, "unrecognized command 'version'") {
			// ZFS on Linux before 0.8 has no `zfs version`. The loaded
			// kernel module reports its release.
			if v, err := zfsKmodVersion(z.MqlRuntime); err != nil {
				return "", err
			} else if v != "" {
				return v, nil
			}
			// Oracle Solaris has no `zfs version` either. It names its ZFS
			// release by the pool version instead.
			out, _, err := runZfsCommand(z.MqlRuntime, "zpool upgrade -v", "zfs version")
			if err != nil {
				return "", err
			}
			if v, ok := zfs.ParseSolarisPoolVersion(out); ok {
				return v, nil
			}
		}
		return "", errors.New("could not retrieve zfs version: " + cmd.Stderr.Data)
	}
	version := strings.TrimSpace(cmd.Stdout.Data)
	if i := strings.IndexByte(version, '\n'); i != -1 {
		version = version[:i]
	}
	return version, nil
}

// zfsKmodVersion reads the release of the loaded ZFS on Linux kernel module
// from /sys/module/zfs/version and returns it the way `zfs version` names the
// module on its second line (zfs-kmod-0.6.5.6-0ubuntu28). It returns "" when
// the file does not exist.
func zfsKmodVersion(runtime *plugin.Runtime) (string, error) {
	o, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData("/sys/module/zfs/version"),
	})
	if err != nil {
		return "", err
	}
	f := o.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return "", exists.Error
	}
	if !exists.Data {
		return "", nil
	}
	content := f.GetContent()
	if content.Error != nil {
		return "", content.Error
	}
	v := strings.TrimSpace(content.Data)
	if v == "" {
		return "", nil
	}
	return "zfs-kmod-" + v, nil
}

func (z *mqlZfs) pools() ([]any, error) {
	out, err := runZfsJSONOrText(z.MqlRuntime, "zfs pools", "zpool get -jp all", "zpool get -Hp all")
	if err != nil && strings.Contains(err.Error(), "missing property argument") {
		// Oracle Solaris zpool get requires the pool names.
		out, err = solarisPoolProperties(z.MqlRuntime)
	}
	if err != nil {
		return nil, err
	}

	var pools []zfs.Pool
	if out.isJSON() {
		pools, err = zfs.ParsePools(out.json)
	} else {
		pools, err = zfs.ParsePoolsText(out.text[0])
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(pools))
	for _, p := range pools {
		r, err := CreateResource(z.MqlRuntime, "zfs.pool", map[string]*llx.RawData{
			"name":           llx.StringData(p.Name),
			"guid":           llx.StringData(p.GUID),
			"health":         llx.StringData(p.Health),
			"sizeBytes":      llx.IntData(p.Size),
			"allocatedBytes": llx.IntData(p.Allocated),
			"freeBytes":      llx.IntData(p.Free),
			"fragmentation":  llx.IntDataPtr(p.Fragmentation),
			"percentUsed":    llx.IntData(p.PercentUsed),
			"dedupratio":     llx.FloatData(p.Dedupratio),
			"readonly":       llx.BoolData(p.Readonly),
			"autoexpand":     llx.BoolData(p.Autoexpand),
			"autoreplace":    llx.BoolData(p.Autoreplace),
			"autotrim":       llx.BoolData(p.Autotrim),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (z *mqlZfs) datasets() ([]any, error) {
	out, err := runZfsJSONOrText(z.MqlRuntime, "zfs datasets", "zfs get -jp all", "zfs get -Hp all")
	if err != nil {
		return nil, err
	}

	var datasets []zfs.Dataset
	if out.isJSON() {
		datasets, err = zfs.ParseDatasets(out.json)
	} else {
		datasets, err = zfs.ParseDatasetsText(out.text[0])
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(datasets))
	for _, ds := range datasets {
		r, err := CreateResource(z.MqlRuntime, "zfs.dataset", map[string]*llx.RawData{
			"name":             llx.StringData(ds.Name),
			"type":             llx.StringData(ds.Type),
			"usedBytes":        llx.IntData(ds.Used),
			"availableBytes":   llx.IntData(ds.Available),
			"referencedBytes":  llx.IntData(ds.Referenced),
			"mountpoint":       llx.StringData(ds.Mountpoint),
			"compression":      llx.StringData(ds.Compression),
			"compressratio":    llx.FloatData(ds.Compressratio),
			"mounted":          llx.BoolData(ds.Mounted),
			"recordsizeBytes":  llx.IntData(ds.Recordsize),
			"quotaBytes":       llx.IntData(ds.Quota),
			"reservationBytes": llx.IntData(ds.Reservation),
			"origin":           llx.StringData(ds.Origin),
			"creation":         llx.TimeDataPtr(ds.Creation),
			"encryption":       llx.StringData(ds.Encryption),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// solarisPoolProperties runs `zpool get -Hp all` with every pool named, which
// Oracle Solaris requires.
func solarisPoolProperties(runtime *plugin.Runtime) (zfsOutput, error) {
	names, _, err := runZfsCommand(runtime, "zpool list -H -o name", "zfs pools")
	if err != nil {
		return zfsOutput{}, err
	}
	cmd := "zpool get -Hp all"
	for name := range strings.FieldsSeq(names) {
		if !validZfsName.MatchString(name) {
			return zfsOutput{}, fmt.Errorf("invalid zfs pool name: %q", name)
		}
		cmd += fmt.Sprintf(" %q", name)
	}
	if cmd == "zpool get -Hp all" {
		return zfsOutput{text: []string{""}}, nil
	}
	out, _, err := runZfsCommand(runtime, cmd, "zfs pools")
	if err != nil {
		return zfsOutput{}, err
	}
	return zfsOutput{text: []string{out}}, nil
}

// zfs.pool

func (p *mqlZfsPool) id() (string, error) {
	return "zfs.pool/" + p.Name.Data, nil
}

func initZfsPool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "zfs", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	z := obj.(*mqlZfs)
	pools := z.GetPools()
	if pools.Error != nil {
		return nil, nil, pools.Error
	}

	for i := range pools.Data {
		pool := pools.Data[i].(*mqlZfsPool)
		if pool.Name.Data == name {
			return nil, pool, nil
		}
	}

	return nil, nil, errors.New("zfs pool not found: " + name)
}

func (p *mqlZfsPool) vdevs() ([]any, error) {
	if !validZfsName.MatchString(p.Name.Data) {
		return nil, fmt.Errorf("invalid zfs pool name: %q", p.Name.Data)
	}
	out, err := runZfsJSONOrText(p.MqlRuntime, "zfs pool vdevs",
		fmt.Sprintf("zpool status -jp %q", p.Name.Data),
		fmt.Sprintf("zpool status -ps %q", p.Name.Data),
		fmt.Sprintf("zpool status -Pps %q", p.Name.Data),
	)

	var vdevs []zfs.Vdev
	switch {
	case err != nil && strings.Contains(err.Error(), "invalid option"):
		// ZFS on Linux before 0.8 has neither -p nor -s, but has -P. Oracle
		// Solaris zpool status has neither -p, -s nor -P.
		var text, fullText string
		text, _, err = runZfsCommand(p.MqlRuntime, fmt.Sprintf("zpool status %q", p.Name.Data), "zfs pool vdevs")
		if err != nil {
			return nil, err
		}
		fullText, _, err = runZfsCommand(p.MqlRuntime, fmt.Sprintf("zpool status -P %q", p.Name.Data), "zfs pool vdevs")
		if err != nil {
			if !strings.Contains(err.Error(), "invalid option") {
				return nil, err
			}
			fullText = ""
		}
		vdevs, err = zfs.ParseVdevsTextPlain(text, fullText)
	case err != nil:
		return nil, err
	case out.isJSON():
		vdevs, err = zfs.ParseVdevs(out.json)
	default:
		vdevs, err = zfs.ParseVdevsText(out.text[0], out.text[1])
	}
	if err != nil {
		return nil, err
	}

	return createVdevResources(p.MqlRuntime, p.Name.Data, vdevs)
}

func createVdevResources(runtime *plugin.Runtime, poolName string, vdevs []zfs.Vdev) ([]any, error) {
	res := make([]any, 0, len(vdevs))
	for _, v := range vdevs {
		children, err := createVdevResources(runtime, poolName, v.Devices)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(runtime, "zfs.pool.vdev", map[string]*llx.RawData{
			"name":           llx.StringData(v.Name),
			"type":           llx.StringData(v.Type),
			"state":          llx.StringData(v.State),
			"path":           llx.StringData(v.Path),
			"readErrors":     llx.IntData(v.ReadErrors),
			"writeErrors":    llx.IntData(v.WriteErrors),
			"checksumErrors": llx.IntData(v.ChecksumErrors),
			"slowIos":        llx.IntData(v.SlowIOs),
			"numDevices":     llx.IntData(int64(len(v.Devices))),
			"devices":        llx.ArrayData(children, types.Resource("zfs.pool.vdev")),
		})
		if err != nil {
			return nil, err
		}
		vdev := r.(*mqlZfsPoolVdev)
		vdev.poolName = poolName
		res = append(res, r)
	}
	return res, nil
}

// zfs.pool.vdev

type mqlZfsPoolVdevInternal struct {
	poolName string
}

func (v *mqlZfsPoolVdev) id() (string, error) {
	return "zfs.pool.vdev/" + v.poolName + "/" + v.Name.Data, nil
}

func (p *mqlZfsPool) properties() (map[string]any, error) {
	if !validZfsName.MatchString(p.Name.Data) {
		return nil, fmt.Errorf("invalid zfs pool name: %q", p.Name.Data)
	}
	out, err := runZfsJSONOrText(p.MqlRuntime, "zfs pool properties",
		fmt.Sprintf("zpool get -jp all %q", p.Name.Data),
		fmt.Sprintf("zpool get -Hp all %q", p.Name.Data),
	)
	if err != nil {
		return nil, err
	}

	var props map[string]string
	if out.isJSON() {
		props, err = zfs.ParseProperties(out.json)
	} else {
		props, err = zfs.ParsePropertiesText(out.text[0])
	}
	if err != nil {
		return nil, err
	}

	result := make(map[string]any, len(props))
	for k, v := range props {
		result[k] = v
	}
	return result, nil
}

// zfs.dataset

func (d *mqlZfsDataset) id() (string, error) {
	return "zfs.dataset/" + d.Name.Data, nil
}

func initZfsDataset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "zfs", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	z := obj.(*mqlZfs)
	datasets := z.GetDatasets()
	if datasets.Error != nil {
		return nil, nil, datasets.Error
	}

	for i := range datasets.Data {
		ds := datasets.Data[i].(*mqlZfsDataset)
		if ds.Name.Data == name {
			return nil, ds, nil
		}
	}

	return nil, nil, errors.New("zfs dataset not found: " + name)
}

func (d *mqlZfsDataset) properties() (map[string]any, error) {
	if !validZfsName.MatchString(d.Name.Data) {
		return nil, fmt.Errorf("invalid zfs dataset name: %q", d.Name.Data)
	}
	out, err := runZfsJSONOrText(d.MqlRuntime, "zfs dataset properties",
		fmt.Sprintf("zfs get -jp all %q", d.Name.Data),
		fmt.Sprintf("zfs get -Hp all %q", d.Name.Data),
	)
	if err != nil {
		return nil, err
	}

	var props map[string]string
	if out.isJSON() {
		props, err = zfs.ParseProperties(out.json)
	} else {
		props, err = zfs.ParsePropertiesText(out.text[0])
	}
	if err != nil {
		return nil, err
	}

	result := make(map[string]any, len(props))
	for k, v := range props {
		result[k] = v
	}
	return result, nil
}

func (d *mqlZfsDataset) snapshots() ([]any, error) {
	obj, err := CreateResource(d.MqlRuntime, "zfs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	z := obj.(*mqlZfs)
	datasets := z.GetDatasets()
	if datasets.Error != nil {
		return nil, datasets.Error
	}

	prefix := d.Name.Data + "@"
	var snapshots []any
	for i := range datasets.Data {
		ds := datasets.Data[i].(*mqlZfsDataset)
		if ds.Type.Data == "snapshot" && strings.HasPrefix(ds.Name.Data, prefix) {
			snapshots = append(snapshots, ds)
		}
	}
	return snapshots, nil
}
