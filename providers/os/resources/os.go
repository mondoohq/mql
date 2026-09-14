// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/docker"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/connection/tar"
	"go.mondoo.com/mql/v13/providers/os/id/hostname"
	"go.mondoo.com/mql/v13/providers/os/id/hypervisor"
	"go.mondoo.com/mql/v13/providers/os/id/platformid"
	"go.mondoo.com/mql/v13/providers/os/resources/reboot"
	"go.mondoo.com/mql/v13/providers/os/resources/systemd"
	"go.mondoo.com/mql/v13/providers/os/resources/updates"
	"go.mondoo.com/mql/v13/providers/os/resources/uptime"
	"go.mondoo.com/mql/v13/providers/os/resources/windows"
)

func (p *mqlOs) rebootpending() (bool, error) {
	switch p.MqlRuntime.Connection.(type) {
	case *docker.SnapshotConnection:
		return false, nil
	case *tar.Connection:
		return false, nil
	}

	// check photon
	conn := p.MqlRuntime.Connection.(shared.Connection)
	asset := conn.Asset()

	if asset.Platform.Name == "photon" {
		// get installed kernel and check if the found one is running
		k, err := CreateResource(p.MqlRuntime, "kernel", map[string]*llx.RawData{})
		if err != nil {
			return false, err
		}
		kernel := k.(*mqlKernel)

		kernelInstalled := kernel.GetInstalled()
		if kernelInstalled.Error != nil {
			return false, kernelInstalled.Error
		}

		kernels := []KernelVersion{}
		data, err := json.Marshal(kernelInstalled)
		if err != nil {
			return false, err
		}
		err = json.Unmarshal([]byte(data), &kernels)
		if err != nil {
			return false, err
		}

		// we should only have one kernel here
		if len(kernels) != 1 {
			return false, errors.New("unexpected kernel list result for photon os")
		}

		return !kernels[0].Running, nil
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

func (s *mqlOs) hypervisor() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if res, ok := hypervisor.Hypervisor(conn, platform); ok {
		return res, nil
	}
	s.Hypervisor = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
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

// returns the OS native machine UUID/GUID
func (s *mqlOs) machineid() (string, error) {
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

func (p *mqlOsBase) rebootpending() (bool, error) {
	// it is a container image, a reboot is never required
	switch p.MqlRuntime.Connection.(type) {
	case *docker.SnapshotConnection:
		return false, nil
	case *tar.Connection:
		return false, nil
	}

	// check photon
	conn := p.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if platform.Name == "photon" {
		// get installed kernel and check if the found one is running
		raw, err := CreateResource(p.MqlRuntime, "kernel", map[string]*llx.RawData{})
		if err != nil {
			return false, err
		}
		kernel := raw.(*mqlKernel)
		installed := kernel.GetInstalled()
		if installed.Error != nil {
			return false, installed.Error
		}

		kernels := []KernelVersion{}
		data, err := json.Marshal(installed)
		if err != nil {
			return false, err
		}
		err = json.Unmarshal([]byte(data), &kernels)
		if err != nil {
			return false, err
		}

		// we should only have one kernel here
		if len(kernels) != 1 {
			return false, errors.New("unexpected kernel list result for photon os")
		}

		return !kernels[0].Running, nil
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
