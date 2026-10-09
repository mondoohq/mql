// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sort"
	"strconv"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/kernel"
	"go.mondoo.com/mql/types"
)

// kernelSysctls is the live and configured state of every kernel parameter,
// read once per query by loadSysctls and shared by kernel.sysctls and every
// kernel.parameter.
type kernelSysctls struct {
	// live maps parameter names to their running values, whitespace
	// normalized like configured values.
	live map[string]string
	// observable is false when no running kernel could be read, such as on
	// an image scan. live is empty then, and every parameter's `active` is
	// null rather than false.
	observable bool
	config     *kernel.SysctlConfig
}

type mqlKernelParameterSettingInternal struct {
	path string
}

func (k *mqlKernel) loadSysctls() (*kernelSysctls, error) {
	k.sysctlOnce.Do(func() {
		conn := k.MqlRuntime.Connection.(shared.Connection)

		live, observable, err := readLiveSysctls(conn)
		if err != nil {
			k.sysctlErr = err
			return
		}
		config, err := readSysctlConfig(k.MqlRuntime, conn)
		if err != nil {
			k.sysctlErr = err
			return
		}
		k.sysctlState = &kernelSysctls{live: live, observable: observable, config: config}
	})
	return k.sysctlState, k.sysctlErr
}

// readLiveSysctls reads the running kernel's parameters, and reports whether
// there was a running kernel to read.
//
// There is none when the connection can't run commands and the target has
// no /proc/sys: an image or a mounted filesystem. That is decided before
// reading, so a read that is attempted and fails is returned as an error
// rather than reported as "no kernel". A running Linux, macOS or BSD kernel
// exposes hundreds of parameters, so an empty result also means nothing was
// read: on Linux the /proc/sys walk skips entries it can't read rather than
// failing.
func readLiveSysctls(conn shared.Connection) (map[string]string, bool, error) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		if _, err := conn.FileSystem().Stat("/proc/sys"); err != nil {
			return map[string]string{}, false, nil
		}
	}

	mm, err := kernel.ResolveManager(conn)
	if err != nil {
		return nil, false, err
	}
	params, err := mm.Parameters()
	if err != nil {
		return nil, false, err
	}
	if len(params) == 0 {
		return map[string]string{}, false, nil
	}

	live := make(map[string]string, len(params))
	for name, value := range params {
		live[name] = kernel.NormalizeSysctlValue(value)
	}
	return live, true, nil
}

// readSysctlConfig parses the configuration files the platform applies, in
// the order it applies them. A file that exists but can't be read is an
// error: leaving it out would report a configured value that isn't the one
// the system applies.
func readSysctlConfig(runtime *plugin.Runtime, conn shared.Connection) (*kernel.SysctlConfig, error) {
	// listConfDFiles returns the files it could list alongside the error for
	// a directory it couldn't. modprobe uses that partial list; here it is
	// rejected, because a missing directory can hide the file whose
	// assignment wins, and configured would name a value the system does
	// not apply.
	files, err := sysctlConfigFiles(runtime, conn)
	if err != nil {
		return nil, err
	}

	fs := conn.FileSystem()
	config := kernel.NewSysctlConfig()
	for _, path := range files {
		f, err := fs.Open(path)
		if err != nil {
			return nil, err
		}
		if conn.Asset().Platform.Name == "aix" {
			err = config.ParseAixNextboot(f, path)
		} else {
			err = config.Parse(f, path)
		}
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// sysctlConfigFiles returns the sysctl configuration files the platform
// applies at boot, in order.
//
// On Linux these are the sysctl.d files. systemd-sysctl, which applies them
// at boot on a systemd host, does not read /etc/sysctl.conf; distributions
// link it in as /etc/sysctl.d/99-sysctl.conf, so it is applied in that
// position. Without systemd-sysctl, procps `sysctl --system` is what applies
// them, and it reads /etc/sysctl.conf after every sysctl.d file.
func sysctlConfigFiles(runtime *plugin.Runtime, conn shared.Connection) ([]string, error) {
	fs := conn.FileSystem()
	platform := conn.Asset().Platform

	switch {
	case platform.Name == "solaris":
		return nil, nil
	case platform.Name == "aix":
		return existingRegularFiles(fs, kernel.AixNextbootFile), nil
	case platform.IsFamily("linux"):
		files, err := listConfDFiles(runtime, kernel.SysctlDirs)
		if err != nil {
			return nil, err
		}
		if !anyRegularFile(fs, kernel.SystemdSysctlBinaries...) {
			files = append(files, existingRegularFiles(fs, kernel.SysctlConf)...)
		}
		return files, nil
	case platform.Name == "freebsd":
		return existingRegularFiles(fs, kernel.SysctlConf, "/etc/sysctl.conf.local"), nil
	case platform.IsFamily("darwin") || platform.IsFamily("bsd"):
		return existingRegularFiles(fs, kernel.SysctlConf), nil
	}
	return nil, nil
}

// existingRegularFiles returns the paths that exist and are not directories,
// following symlinks.
func existingRegularFiles(fs afero.Fs, paths ...string) []string {
	var res []string
	for _, p := range paths {
		if fi, err := fs.Stat(p); err == nil && !fi.IsDir() {
			res = append(res, p)
		}
	}
	return res
}

func anyRegularFile(fs afero.Fs, paths ...string) bool {
	return len(existingRegularFiles(fs, paths...)) > 0
}

func (k *mqlKernel) sysctls() ([]any, error) {
	state, err := k.loadSysctls()
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{}, len(state.live))
	for name := range state.live {
		names[name] = struct{}{}
	}
	for _, name := range state.config.Names() {
		if _, ok := names[name]; ok {
			continue
		}
		// A glob takes part through the live parameters it matches. Only
		// one that matches none is listed under its pattern, so that no
		// configured setting goes missing from the list.
		if kernel.IsSysctlGlob(name) && globMatchesAny(name, state.live) {
			continue
		}
		names[name] = struct{}{}
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	res := make([]any, 0, len(sorted))
	for _, name := range sorted {
		args, err := kernelParameterArgs(k.MqlRuntime, state, name)
		if err != nil {
			return nil, err
		}
		p, err := CreateResource(k.MqlRuntime, "kernel.parameter", args)
		if err != nil {
			return nil, err
		}
		res = append(res, p)
	}
	return res, nil
}

func globMatchesAny(pattern string, live map[string]string) bool {
	for name := range live {
		if kernel.MatchSysctlGlob(pattern, name) {
			return true
		}
	}
	return false
}

func initKernelParameter(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("kernel.parameter requires a name")
	}

	obj, err := CreateResource(runtime, "kernel", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	state, err := obj.(*mqlKernel).loadSysctls()
	if err != nil {
		return nil, nil, err
	}

	res, err := kernelParameterArgs(runtime, state, name)
	return res, nil, err
}

// kernelParameterArgs builds the fields of one kernel.parameter from the
// live and configured state.
func kernelParameterArgs(runtime *plugin.Runtime, state *kernelSysctls, name string) (map[string]*llx.RawData, error) {
	name = kernel.NormalizeSysctlName(name)
	args := map[string]*llx.RawData{
		"__id":       llx.StringData("kernel.parameter/" + name),
		"name":       llx.StringData(name),
		"active":     llx.NilData,
		"value":      llx.NilData,
		"configured": llx.NilData,
	}

	if state.observable {
		value, ok := state.live[name]
		args["active"] = llx.BoolData(ok)
		if ok {
			args["value"] = llx.StringData(value)
		}
	}

	assignments, effective := state.config.Lookup(name)
	if effective >= 0 {
		args["configured"] = llx.StringData(assignments[effective].Value)
	}

	settings := make([]any, len(assignments))
	for i, a := range assignments {
		s, err := CreateResource(runtime, "kernel.parameter.setting", map[string]*llx.RawData{
			"__id":         llx.StringData("kernel.parameter.setting/" + name + "/" + a.File + ":" + strconv.Itoa(a.Line)),
			"key":          llx.StringData(a.Key),
			"value":        llx.StringData(a.Value),
			"line":         llx.IntData(int64(a.Line)),
			"effective":    llx.BoolData(i == effective),
			"ignoreErrors": llx.BoolData(a.IgnoreErrors),
		})
		if err != nil {
			return nil, err
		}
		setting := s.(*mqlKernelParameterSetting)
		setting.path = a.File
		settings[i] = setting
	}
	args["settings"] = llx.ArrayData(settings, types.Resource("kernel.parameter.setting"))

	return args, nil
}

func (s *mqlKernelParameterSetting) file() (*mqlFile, error) {
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(s.path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}
