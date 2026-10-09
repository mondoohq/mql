// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/core/resources/versions/rpm"
	"go.mondoo.com/mql/providers/os/connection/docker"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/providers/os/detector/containerenv"
	"go.mondoo.com/mql/providers/os/id/hostname"
	"go.mondoo.com/mql/providers/os/id/hypervisor"
	"go.mondoo.com/mql/providers/os/id/platformid"
	"go.mondoo.com/mql/providers/os/resources/reboot"
	"go.mondoo.com/mql/providers/os/resources/systemd"
	"go.mondoo.com/mql/providers/os/resources/updates"
	"go.mondoo.com/mql/providers/os/resources/uptime"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (p *mqlOs) rebootpending() (bool, error) {
	switch p.MqlRuntime.Connection.(type) {
	case *docker.SnapshotConnection:
		return false, nil
	case *tar.Connection:
		return false, nil
	}

	conn := p.MqlRuntime.Connection.(shared.Connection)
	asset := conn.Asset()

	if rebootNeverPending(conn, asset.Platform) {
		return false, nil
	}

	if rebootPendingFromKernelPackages(asset.Platform) {
		k, err := CreateResource(p.MqlRuntime, "kernel", map[string]*llx.RawData{})
		if err != nil {
			return false, err
		}
		return kernelPackagesRebootPending(k.(*mqlKernel).GetInstalled())
	}

	// TODO: move more logic into MQL to leverage its cache
	// try to collect if a reboot is required, fails for static images
	rb, err := reboot.New(conn)
	if err != nil {
		return false, err
	}
	return rb.RebootPending()
}

func (p *mqlOs) getUnixEnv() (map[string]any, error) {
	rawCmd, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("env"),
	})
	if err != nil {
		return nil, err
	}
	cmd := rawCmd.(*mqlCommand)

	out := cmd.GetStdout()
	if out.Error != nil {
		return nil, out.Error
	}

	res := map[string]any{}
	lines := strings.Split(out.Data, "\n")
	for i := range lines {
		parts := strings.SplitN(lines[i], "=", 2)
		if len(parts) != 2 {
			continue
		}
		res[parts[0]] = parts[1]
	}

	return res, nil
}

func (p *mqlOs) getWindowsEnv() (map[string]any, error) {
	rawCmd, err := CreateResource(p.MqlRuntime, "powershell", map[string]*llx.RawData{
		"script": llx.StringData("Get-ChildItem Env:* | ConvertTo-Json"),
	})
	if err != nil {
		return nil, err
	}
	cmd := rawCmd.(*mqlPowershell)

	out := cmd.GetStdout()
	if out.Error != nil {
		return nil, out.Error
	}

	return windows.ParseEnv(strings.NewReader(out.Data))
}

func (p *mqlOs) env() (map[string]any, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if platform.IsFamily("windows") {
		return p.getWindowsEnv()
	}
	return p.getUnixEnv()
}

func (p *mqlOs) path(env map[string]any) ([]any, error) {
	conn, ok := p.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("cannot determine platform for path lookup")
	}
	isWindows := conn.Asset().Platform.IsFamily("windows")

	rawPath, ok := env["PATH"]
	if !ok && isWindows {
		// Windows environment variable names are case-insensitive and the
		// variable comes back from Get-ChildItem Env: as "Path", so the exact
		// "PATH" lookup missed and os.path was empty on every Windows system.
		for k, v := range env {
			if strings.EqualFold(k, "PATH") {
				rawPath, ok = v, true
				break
			}
		}
	}
	if !ok {
		return []any{}, nil
	}

	path, ok := rawPath.(string)
	if !ok {
		return nil, fmt.Errorf("PATH is %T, expected a string", rawPath)
	}

	return splitPathList(path, isWindows), nil
}

// splitPathList splits a PATH value into its entries. Windows separates them
// with ';'; splitting those on ':' cut every entry apart at its drive letter.
// Empty entries are kept: on unix an empty element means the working directory,
// which is worth being able to audit for.
func splitPathList(path string, isWindows bool) []any {
	separator := ":"
	if isWindows {
		separator = ";"
	}

	parts := strings.Split(path, separator)
	res := make([]any, len(parts))
	for i := range parts {
		res[i] = parts[i]
	}
	return res
}

func MqlTime(t time.Time) *time.Time {
	return &t
}

// returns uptime in nanoseconds
func (p *mqlOs) uptime() (*time.Time, error) {
	uptime, err := uptime.New(p.MqlRuntime.Connection.(shared.Connection))
	if err != nil {
		return MqlTime(llx.DurationToTime(0)), err
	}

	t, err := uptime.Duration()
	if err != nil {
		return MqlTime(llx.DurationToTime(0)), err
	}

	// we get nano seconds but duration to time only takes seconds
	bootTime := time.Now().Add(-t)
	up := time.Now().Unix() - bootTime.Unix()
	return MqlTime(llx.DurationToTime(up)), nil
}

func (p *mqlOsUpdate) id() (string, error) {
	return p.Name.Data, nil
}

func (p *mqlOs) updates() ([]any, error) {
	// find suitable system updates
	conn := p.MqlRuntime.Connection.(shared.Connection)
	um, err := updates.ResolveSystemUpdateManager(conn)
	if um == nil || err != nil {
		return nil, fmt.Errorf("could not detect suitable update manager for platform")
	}

	// retrieve all system updates
	updates, err := um.List()
	if err != nil {
		return nil, fmt.Errorf("could not retrieve updates list for platform")
	}

	// create MQL update resources for each update
	osupdates := make([]any, len(updates))
	log.Debug().Int("updates", len(updates)).Msg("mql[updates]> found system updates")
	for i, update := range updates {

		o, err := CreateResource(p.MqlRuntime, "os.update", map[string]*llx.RawData{
			"name":     llx.StringData(update.Name),
			"severity": llx.StringData(update.Severity),
			"category": llx.StringData(update.Category),
			"restart":  llx.BoolData(update.Restart),
			"format":   llx.StringData(update.Format),
		})
		if err != nil {
			return nil, err
		}

		osupdates[i] = o.(*mqlOsUpdate)
	}

	// return the packages as new entries
	return osupdates, nil
}

func (s *mqlOs) hostname() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if res, ok := hostname.Hostname(conn, platform); ok {
		return res, nil
	}
	return "", errors.New("cannot determine hostname")
}

func (s *mqlOsBase) hypervisor() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if res, ok := hypervisor.Hypervisor(conn, platform); ok {
		return res, nil
	}
	s.Hypervisor = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

// The deprecated `os` fields that also exist on the universal root forward to
// it, so the logic has one home while the old name lives out the v14 line.
func (s *mqlOs) hypervisor() (string, error) {
	base, err := osBase(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	v := base.GetHypervisor()
	if v.Error != nil {
		return "", v.Error
	}
	if v.State&plugin.StateIsNull != 0 {
		s.Hypervisor = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return v.Data, nil
}

// osBase returns the universal OS root, which the deprecated `os` accessors
// read through.
func osBase(runtime *plugin.Runtime) (*mqlOsBase, error) {
	res, err := CreateResource(runtime, "os.base", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOsBase), nil
}

func (p *mqlOs) name() (string, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if !platform.IsFamily(inventory.FAMILY_UNIX) && !platform.IsFamily(inventory.FAMILY_WINDOWS) {
		return "", errors.New("your platform is not supported by operating system resource")
	}

	if platform.IsFamily(inventory.FAMILY_LINUX) {
		lf, err := CreateResource(p.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData("/etc/machine-info"),
		})
		if err != nil {
			return "", err
		}
		file := lf.(*mqlFile)

		exists := file.GetExists()
		if exists.Error != nil {
			return "", exists.Error
		}
		// if the file does not exist, the pretty hostname is just empty
		// fallback to hostname
		if !exists.Data {
			hn := p.GetHostname()
			return hn.Data, hn.Error
		}

		// gather content
		data := file.GetContent()
		if data.Error != nil {
			return "", data.Error
		}

		mi, err := systemd.ParseMachineInfo(strings.NewReader(data.Data))
		if err != nil {
			return "", err
		}

		if mi.PrettyHostname != "" {
			return mi.PrettyHostname, nil
		}
	}

	// return plain hostname, this also happens for linux if no pretty name was found
	if platform.IsFamily(inventory.FAMILY_UNIX) {
		hn := p.GetHostname()
		return hn.Data, hn.Error
	}

	if platform.IsFamily(inventory.FAMILY_WINDOWS) {

		// try to get the computer name from env
		env, err := p.getWindowsEnv()
		if err == nil {
			val, ok := env["COMPUTERNAME"]
			if ok {
				return val.(string), nil
			}
		}

		// fallback to hostname
		hn := p.GetHostname()
		return hn.Data, hn.Error
	}

	return "", errors.New("your platform is not supported by operating system resource")
}

func (s *mqlOs) machineid() (string, error) {
	base, err := osBase(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	v := base.GetMachineid()
	if v.Error != nil {
		return "", v.Error
	}
	if v.IsNull() {
		s.Machineid.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return v.Data, nil
}

// returns the OS native machine UUID/GUID
func (s *mqlOsBase) machineid() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	uuidProvider, err := platformid.MachineIDProvider(conn, platform)
	if err != nil {
		return "", errors.Wrap(err, "cannot determine platform uuid")
	}

	if uuidProvider == nil {
		return "", errors.New("cannot determine platform uuid")
	}

	id, err := uuidProvider.ID()
	// Container images and minimal systems ship no machine-id at all
	// (systemd writes it on first boot): there is no id, which is not a
	// failure to read one.
	if errors.Is(err, fs.ErrNotExist) {
		s.Machineid.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if err != nil {
		return "", errors.Wrap(err, "cannot determine platform uuid")
	}

	return id, nil
}

func (p *mqlOsBase) id() (string, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	asset := conn.Asset()

	ident := asset.GetMrn()
	if ident == "" {
		ident = strings.Join(asset.GetPlatformIds(), ",")
	}
	return "os.base(" + ident + ")", nil
}

// rebootNeverPending reports whether the asset is a container, where no reboot
// is ever pending. A container is not booted, it is started from an image, so
// the checks below have nothing to compare against: needs-restarting and
// zypper compare package install times with the host's boot time, and the
// kernel comparison sets an image's kernel package against the host's running
// kernel.
func rebootNeverPending(conn shared.Connection, pf *inventory.Platform) bool {
	return isContainerAsset(conn, pf) || containerenv.InContainer(conn)
}

func (p *mqlOsBase) rebootpending() (bool, error) {
	// it is a container image, a reboot is never required
	switch p.MqlRuntime.Connection.(type) {
	case *docker.SnapshotConnection:
		return false, nil
	case *tar.Connection:
		return false, nil
	}

	conn := p.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if rebootNeverPending(conn, platform) {
		return false, nil
	}

	if rebootPendingFromKernelPackages(platform) {
		raw, err := CreateResource(p.MqlRuntime, "kernel", map[string]*llx.RawData{})
		if err != nil {
			return false, err
		}
		return kernelPackagesRebootPending(raw.(*mqlKernel).GetInstalled())
	}

	// TODO: move more logic into MQL to leverage its cache
	// try to collect if a reboot is required, fails for static images
	rb, err := reboot.New(conn)
	if err != nil {
		return false, err
	}
	return rb.RebootPending()
}

func (p *mqlOsBase) getUnixEnv() (map[string]any, error) {
	rawCmd, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("env"),
	})
	if err != nil {
		return nil, err
	}
	cmd := rawCmd.(*mqlCommand)

	out := cmd.GetStdout()
	if out.Error != nil {
		return nil, out.Error
	}

	res := map[string]any{}
	lines := strings.Split(out.Data, "\n")
	for i := range lines {
		parts := strings.SplitN(lines[i], "=", 2)
		if len(parts) != 2 {
			continue
		}
		res[parts[0]] = parts[1]
	}

	return res, nil
}

func (p *mqlOsBase) getWindowsEnv() (map[string]any, error) {
	rawCmd, err := CreateResource(p.MqlRuntime, "powershell", map[string]*llx.RawData{
		"script": llx.StringData("Get-ChildItem Env:* | ConvertTo-Json"),
	})
	if err != nil {
		return nil, err
	}
	cmd := rawCmd.(*mqlPowershell)

	out := cmd.GetStdout()
	if out.Error != nil {
		return nil, out.Error
	}

	return windows.ParseEnv(strings.NewReader(out.Data))
}

func (p *mqlOsBase) env() (map[string]any, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if platform.IsFamily("windows") {
		return p.getWindowsEnv()
	}
	return p.getUnixEnv()
}

func (p *mqlOsBase) path(env map[string]any) ([]any, error) {
	rawPath, ok := env["PATH"]
	if !ok {
		return []any{}, nil
	}

	path := rawPath.(string)
	parts := strings.Split(path, ":")
	res := make([]any, len(parts))
	for i := range parts {
		res[i] = parts[i]
	}

	return res, nil
}

// returns uptime in nanoseconds
func (p *mqlOsBase) uptime() (*time.Time, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	uptime, err := uptime.New(conn)
	if err != nil {
		return MqlTime(llx.DurationToTime(0)), err
	}

	t, err := uptime.Duration()
	if err != nil {
		return MqlTime(llx.DurationToTime(0)), err
	}

	// we get nano seconds but duration to time only takes seconds
	bootTime := time.Now().Add(-t)
	up := time.Now().Unix() - bootTime.Unix()
	return MqlTime(llx.DurationToTime(up)), nil
}

func (p *mqlOsBase) updates() ([]any, error) {
	// find suitable system updates
	conn := p.MqlRuntime.Connection.(shared.Connection)
	um, err := updates.ResolveSystemUpdateManager(conn)
	if um == nil || err != nil {
		return nil, fmt.Errorf("could not detect suitable update manager for platform")
	}

	// retrieve all system updates
	updates, err := um.List()
	if err != nil {
		return nil, fmt.Errorf("could not retrieve updates list for platform")
	}

	// create MQL update resources for each update
	osupdates := make([]any, len(updates))
	log.Debug().Int("updates", len(updates)).Msg("mql[updates]> found system updates")
	for i, update := range updates {

		o, err := CreateResource(p.MqlRuntime, "os.update", map[string]*llx.RawData{
			"name":     llx.StringData(update.Name),
			"severity": llx.StringData(update.Severity),
			"category": llx.StringData(update.Category),
			"restart":  llx.BoolData(update.Restart),
			"format":   llx.StringData(update.Format),
		})
		if err != nil {
			return nil, err
		}

		osupdates[i] = o.(*mqlOsUpdate)
	}

	// return the packages as new entries
	return osupdates, nil
}

func (s *mqlOsBase) hostname() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if res, ok := hostname.Hostname(conn, platform); ok {
		return res, nil
	}
	return "", errors.New("cannot determine hostname")
}

func (p *mqlOsBase) name() (string, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if !platform.IsFamily(inventory.FAMILY_UNIX) && !platform.IsFamily(inventory.FAMILY_WINDOWS) {
		return "", errors.New("your platform is not supported by operating system resource")
	}

	if platform.IsFamily(inventory.FAMILY_LINUX) {
		lf, err := CreateResource(p.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData("/etc/machine-info"),
		})
		if err != nil {
			return "", err
		}
		file := lf.(*mqlFile)

		exists := file.GetExists()
		if exists.Error != nil {
			return "", exists.Error
		}
		// if the file does not exist, the pretty hostname is just empty
		if !exists.Data {
			return "", nil
		}

		// gather content
		data := file.GetContent()
		if data.Error != nil {
			return "", data.Error
		}

		mi, err := systemd.ParseMachineInfo(strings.NewReader(data.Data))
		if err != nil {
			return "", err
		}

		if mi.PrettyHostname != "" {
			return mi.PrettyHostname, nil
		}
	}

	// return plain hostname, this also happens for linux if no pretty name was found
	if platform.IsFamily(inventory.FAMILY_UNIX) {
		if res, ok := hostname.Hostname(conn, platform); ok {
			return res, nil
		}
		return "", errors.New("cannot determine hostname")
	}

	if platform.IsFamily(inventory.FAMILY_WINDOWS) {

		// try to get the computer name from env
		env, err := p.getWindowsEnv()
		if err == nil {
			val, ok := env["COMPUTERNAME"]
			if ok {
				return val.(string), nil
			}
		}

		// fallback to hostname
		if res, ok := hostname.Hostname(conn, platform); ok {
			return res, nil
		}
		return "", errors.New("cannot determine hostname")
	}

	return "", errors.New("your platform is not supported by operating system resource")
}

func (s *mqlOsBase) machine() (*mqlMachine, error) {
	res, err := CreateResource(s.MqlRuntime, "machine", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMachine), nil
}

func (s *mqlOsBase) groups() (*mqlGroups, error) {
	res, err := CreateResource(s.MqlRuntime, "groups", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGroups), nil
}

func (s *mqlOsBase) users() (*mqlUsers, error) {
	res, err := CreateResource(s.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlUsers), nil
}

func (s *mqlOsUnix) id() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	asset := conn.Asset()

	ident := asset.GetMrn()
	if ident == "" {
		ident = strings.Join(asset.GetPlatformIds(), ",")
	}
	return "os.unix(" + ident + ")", nil
}

func (s *mqlOsUnix) base() (*mqlOsBase, error) {
	res, err := CreateResource(s.MqlRuntime, "os.base", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOsBase), nil
}

func (s *mqlOsLinux) id() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	asset := conn.Asset()

	ident := asset.GetMrn()
	if ident == "" {
		ident = strings.Join(asset.GetPlatformIds(), ",")
	}
	return "os.linux(" + ident + ")", nil
}

func (s *mqlOsLinux) unix() (*mqlOsUnix, error) {
	res, err := CreateResource(s.MqlRuntime, "os.unix", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOsUnix), nil
}

// The family roots and the union receiver identify the asset they describe, the
// same way os.unix and os.linux do, and reach their embedded parent through an
// accessor rather than holding a copy of it. See ADR 031.
func (s *mqlOsWindows) id() (string, error) {
	return rootID(s.MqlRuntime, "os.windows")
}

func (s *mqlOsWindows) base() (*mqlOsBase, error) {
	return osBase(s.MqlRuntime)
}

func (s *mqlOsMacos) id() (string, error) {
	return rootID(s.MqlRuntime, "os.macos")
}

func (s *mqlOsMacos) unix() (*mqlOsUnix, error) {
	res, err := CreateResource(s.MqlRuntime, "os.unix", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOsUnix), nil
}

func (s *mqlOsAny) id() (string, error) {
	return rootID(s.MqlRuntime, "os.any")
}

func (s *mqlOsAny) base() (*mqlOsBase, error) {
	return osBase(s.MqlRuntime)
}

// rootID names a root after the asset it describes, so two assets in one scan
// never share a root instance in the resource cache.
func rootID(runtime *plugin.Runtime, root string) (string, error) {
	conn := runtime.Connection.(shared.Connection)
	asset := conn.Asset()

	ident := asset.GetMrn()
	if ident == "" {
		ident = strings.Join(asset.GetPlatformIds(), ",")
	}
	return root + "(" + ident + ")", nil
}

func (s *mqlOsLinux) iptables() (*mqlIptables, error) {
	res, err := CreateResource(s.MqlRuntime, "iptables", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlIptables), nil
}

func (s *mqlOsLinux) ip6tables() (*mqlIp6tables, error) {
	res, err := CreateResource(s.MqlRuntime, "ip6tables", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlIp6tables), nil
}

func (s *mqlOsLinux) nftables() (*mqlNftables, error) {
	res, err := CreateResource(s.MqlRuntime, "nftables", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNftables), nil
}

func (s *mqlOsLinux) ufw() (*mqlUfw, error) {
	res, err := CreateResource(s.MqlRuntime, "ufw", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlUfw), nil
}

func (s *mqlOsLinux) firewalld() (*mqlFirewalld, error) {
	res, err := CreateResource(s.MqlRuntime, "firewalld", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFirewalld), nil
}

func (s *mqlOsLinux) fstab() (*mqlFstab, error) {
	// NewResource, not CreateResource: only NewResource runs initFstab, which
	// supplies the default /etc/fstab path. Without it the resource is built
	// with an empty path and every read fails with "file does not exist".
	res, err := NewResource(s.MqlRuntime, "fstab", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFstab), nil
}

func (s *mqlOsLinux) apparmor() (*mqlApparmor, error) {
	res, err := CreateResource(s.MqlRuntime, "apparmor", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlApparmor), nil
}

// rebootPendingFromKernelPackages reports whether os.rebootpending is decided
// from kernel.installed on this platform, by kernelPackagesRebootPending.
// These are the platforms with no reboot marker of their own whose kernel
// packages kernel.installed knows how to match with the running kernel.
//
// From the arch family only Arch and EndeavourOS, which ship Arch's kernel
// packages: Manjaro, SteamOS and CachyOS name theirs differently, so
// kernel.installed would find none and the answer would be a confident false.
func rebootPendingFromKernelPackages(pf *inventory.Platform) bool {
	switch pf.Name {
	case "photon", "azurelinux", "mariner", "mageia", "arch", "endeavouros", "void":
		return true
	}
	return false
}

// kernelPackagesRebootPending decides os.rebootpending from the value of
// kernel.installed.
//
// It decodes the list itself (installed.Data), not the TValue wrapper around
// it: the wrapper marshals to a JSON object, which can never decode into
// []KernelVersion.
//
// The answer is:
//   - false when no kernel package is installed. That is the normal state of
//     a container, which runs the host's kernel; there is nothing on disk to
//     boot into.
//   - true when kernel packages are installed but none of them is the running
//     kernel, which is what an in-place kernel upgrade leaves behind (pacman
//     on Arch, xbps on Void, which keep one version per kernel package).
//   - true when a package of the same name as the running kernel is at a
//     newer version, for kernels installed side by side (rpm on Photon,
//     Mageia and Azure Linux). Only the same name counts, so a second kernel
//     line installed beside the running one (Mageia's kernel-server beside a
//     running kernel-desktop, Azure Linux's kernel-hwe beside kernel) does
//     not by itself make a reboot pending.
//   - false otherwise.
//
// kernel.installed on Photon also lists linux-* packages that are not kernels
// (linux-api-headers, linux-esx-devel). They never match the running kernel
// and share no name with it, so they do not affect the answer.
func kernelPackagesRebootPending(installed *plugin.TValue[[]any]) (bool, error) {
	if installed.Error != nil {
		return false, installed.Error
	}

	data, err := json.Marshal(installed.Data)
	if err != nil {
		return false, err
	}
	kernels := []KernelVersion{}
	if err := json.Unmarshal(data, &kernels); err != nil {
		return false, err
	}

	if len(kernels) == 0 {
		return false, nil
	}

	var running *KernelVersion
	for i := range kernels {
		if kernels[i].Running {
			running = &kernels[i]
			break
		}
	}
	if running == nil {
		return true, nil
	}

	var parser rpm.Parser
	for i := range kernels {
		if kernels[i].Running || kernels[i].Name != running.Name {
			continue
		}
		cmp, err := parser.Compare(kernels[i].Version, running.Version)
		if err != nil {
			return false, err
		}
		if cmp > 0 {
			return true, nil
		}
	}
	return false, nil
}
