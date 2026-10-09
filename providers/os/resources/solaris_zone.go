// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/solariszone"
	"go.mondoo.com/mql/types"
)

// zoneadmPath is where Oracle Solaris and illumos install zoneadm. Its
// presence decides whether the system has zones at all. The platform name
// cannot: Solaris 11.4 ships /etc/os-release and is detected into the linux
// family, and the illumos distributions each carry their own name.
const zoneadmPath = "/usr/sbin/zoneadm"

// validZoneName matches a zone name as zonecfg accepts it: an alphanumeric
// followed by alphanumerics, hyphens, underscores and dots.
var validZoneName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func (z *mqlSolarisZones) id() (string, error) {
	return "solaris.zones", nil
}

func (z *mqlSolarisZones) list() ([]any, error) {
	conn := z.MqlRuntime.Connection.(shared.Connection)
	if pf := conn.Asset().GetPlatform(); pf != nil && pf.IsFamily("windows") {
		return []any{}, nil
	}

	f, err := CreateResource(z.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(zoneadmPath),
	})
	if err != nil {
		return nil, err
	}
	exists := f.(*mqlFile).GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		// No zones on this system.
		return []any{}, nil
	}

	o, err := CreateResource(z.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(zoneadmPath + " list -cp"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return nil, exit.Error
	} else if exit.Data != 0 {
		return nil, errors.New("could not list zones: " + strings.TrimSpace(cmd.GetStderr().Data))
	}

	zones, err := solariszone.ParseZoneadmList(cmd.GetStdout().Data)
	if err != nil {
		return nil, llx.MalformedData(err)
	}

	res := make([]any, 0, len(zones))
	for _, zn := range zones {
		r, err := CreateResource(z.MqlRuntime, "solaris.zone", map[string]*llx.RawData{
			"name":   llx.StringData(zn.Name),
			"zoneId": llx.IntDataPtr(zn.ID),
			"state":  llx.StringData(zn.State),
			"path":   llx.StringData(zn.Path),
			"uuid":   llx.StringData(zn.UUID),
			"brand":  llx.StringData(zn.Brand),
			"ipType": llx.StringData(zn.IPType),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// solaris.zone

type mqlSolarisZoneInternal struct {
	lock     sync.Mutex
	settings *solariszone.Settings
}

func (z *mqlSolarisZone) id() (string, error) {
	return "solaris.zone/" + z.Name.Data, nil
}

func initSolarisZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("solaris.zone requires a name")
	}
	name, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, errors.New("solaris.zone name must be a string")
	}

	obj, err := CreateResource(runtime, "solaris.zones", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlSolarisZones).GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, r := range list.Data {
		if zn := r.(*mqlSolarisZone); zn.Name.Data == name {
			return nil, zn, nil
		}
	}
	return nil, nil, fmt.Errorf("solaris.zone with name %q not found", name)
}

// loadConfig reads the zone's configuration with zonecfg once and sets every
// field that comes from it, except datasets, which needs the zfs dataset list
// and resolves on its own.
func (z *mqlSolarisZone) loadConfig() (*solariszone.Settings, error) {
	z.lock.Lock()
	defer z.lock.Unlock()
	if z.settings != nil {
		return z.settings, nil
	}

	cfg, err := z.readConfig()
	if err != nil {
		return nil, err
	}
	s, err := cfg.Settings()
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("zone %s: %w", z.Name.Data, err))
	}
	if err := z.setConfigFields(s); err != nil {
		return nil, err
	}
	z.settings = s
	return s, nil
}

// readConfig runs `zonecfg info -a`. Oracle Solaris 11.4 leaves every
// property at its default out of `info` and `export` without -a, which would
// report an anet's default mac-nospoof link protection as no protection.
// zonecfg releases without -a print every property in `info` and reject the
// flag; they are asked again without it.
func (z *mqlSolarisZone) readConfig() (*solariszone.Config, error) {
	name := z.Name.Data
	if !validZoneName.MatchString(name) {
		return nil, fmt.Errorf("invalid zone name: %q", name)
	}

	out, stderr, err := runZonecfg(z.MqlRuntime, "zonecfg -z "+name+" info -a")
	if err == nil && stderr != "" && isZonecfgUsageError(stderr) {
		out, stderr, err = runZonecfg(z.MqlRuntime, "zonecfg -z "+name+" info")
	}
	if err != nil {
		return nil, err
	}
	if stderr != "" {
		return nil, classifyZonecfgError(name, stderr)
	}
	cfg, err := solariszone.ParseInfo(out)
	if err != nil {
		return nil, llx.MalformedData(err)
	}
	return cfg, nil
}

// runZonecfg runs a zonecfg command line. A non-zero exit is reported through
// the returned stderr, which is then never empty.
func runZonecfg(runtime *plugin.Runtime, cmdline string) (string, string, error) {
	cmd, err := runSbinCommand(runtime, cmdline)
	if err != nil {
		return "", "", err
	}
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", "", exit.Error
	}
	if exit.Data != 0 {
		stderr := strings.TrimSpace(cmd.GetStderr().Data)
		if stderr == "" {
			stderr = strings.TrimSpace(cmd.GetStdout().Data)
		}
		if stderr == "" {
			stderr = "exit status " + strconv.FormatInt(exit.Data, 10)
		}
		return "", stderr, nil
	}
	return cmd.GetStdout().Data, "", nil
}

func isZonecfgUsageError(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "usage") || strings.Contains(lower, "illegal option") ||
		strings.Contains(lower, "invalid option") || strings.Contains(lower, "unknown option")
}

// classifyZonecfgError turns a failed zonecfg run into an error, classified
// by what zonecfg said.
func classifyZonecfgError(zone string, stderr string) error {
	err := fmt.Errorf("could not read the configuration of zone %s: %s", zone, stderr)
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "permission denied") || strings.Contains(lower, "not authorized"):
		return llx.Forbidden(err)
	case strings.Contains(lower, "only be run from the global zone"):
		// Inside a non-global zone, zoneadm lists the zone itself but its
		// configuration is only readable from the global zone.
		return llx.NotApplicable(err)
	}
	return err
}

func optStringValue(v *string) plugin.TValue[string] {
	if v == nil {
		return plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[string]{Data: *v, State: plugin.StateIsSet}
}

func optIntValue(v *int64) plugin.TValue[int64] {
	if v == nil {
		return plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[int64]{Data: *v, State: plugin.StateIsSet}
}

func optListValue(v []string) plugin.TValue[[]any] {
	if v == nil {
		return plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[[]any]{Data: stringsToAny(v), State: plugin.StateIsSet}
}

func (z *mqlSolarisZone) setConfigFields(s *solariszone.Settings) error {
	networks, err := z.createNetworks(s.Networks)
	if err != nil {
		return err
	}
	filesystems, err := z.createFilesystems(s.Filesystems)
	if err != nil {
		return err
	}
	devices, err := z.createDevices(s.Devices)
	if err != nil {
		return err
	}

	if s.Autoboot == nil {
		z.Autoboot = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
	} else {
		z.Autoboot = plugin.TValue[bool]{Data: *s.Autoboot, State: plugin.StateIsSet}
	}
	if s.CPUCap == nil {
		z.CpuCap = plugin.TValue[float64]{State: plugin.StateIsSet | plugin.StateIsNull}
	} else {
		z.CpuCap = plugin.TValue[float64]{Data: *s.CPUCap, State: plugin.StateIsSet}
	}
	z.Bootargs = optStringValue(s.Bootargs)
	z.Limitpriv = optListValue(s.Limitpriv)
	z.FileMacProfile = optStringValue(s.FileMacProfile)
	z.FsAllowed = optListValue(s.FsAllowed)
	z.SchedulingClass = optStringValue(s.SchedulingClass)
	z.Hostid = optStringValue(s.Hostid)
	z.MemoryCapBytes = optIntValue(s.MemoryCapBytes)
	z.SwapCapBytes = optIntValue(s.SwapCapBytes)
	z.LockedMemoryCapBytes = optIntValue(s.LockedMemoryCapBytes)
	z.DedicatedCpus = plugin.TValue[string]{Data: s.DedicatedCPUs, State: plugin.StateIsSet}
	z.MaxLwps = optIntValue(s.MaxLwps)
	z.MaxProcesses = optIntValue(s.MaxProcesses)
	z.Networks = plugin.TValue[[]any]{Data: networks, State: plugin.StateIsSet}
	z.Filesystems = plugin.TValue[[]any]{Data: filesystems, State: plugin.StateIsSet}
	z.Devices = plugin.TValue[[]any]{Data: devices, State: plugin.StateIsSet}
	return nil
}

func (z *mqlSolarisZone) createNetworks(networks []solariszone.Network) ([]any, error) {
	res := make([]any, 0, len(networks))
	for i, n := range networks {
		properties := make(map[string]any, len(n.Properties))
		for k, v := range n.Properties {
			properties[k] = v
		}
		o, err := CreateResource(z.MqlRuntime, "solaris.zone.network", map[string]*llx.RawData{
			"__id":             llx.StringData(fmt.Sprintf("solaris.zone.network/%s/%d", z.Name.Data, i)),
			"type":             llx.StringData(n.Type),
			"name":             llx.StringData(n.Name),
			"lowerLink":        llx.StringData(n.LowerLink),
			"address":          llx.StringData(n.Address),
			"allowedAddresses": llx.ArrayData(stringsToAny(n.AllowedAddresses), types.String),
			"defrouter":        llx.ArrayData(stringsToAny(n.Defrouter), types.String),
			"linkProtection":   llx.ArrayData(stringsToAny(n.LinkProtection), types.String),
			"macAddress":       llx.StringData(n.MacAddress),
			"vlanId":           llx.IntDataPtr(n.VlanID),
			"properties":       llx.MapData(properties, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (z *mqlSolarisZone) createFilesystems(filesystems []solariszone.Filesystem) ([]any, error) {
	res := make([]any, 0, len(filesystems))
	for i, f := range filesystems {
		o, err := CreateResource(z.MqlRuntime, "solaris.zone.filesystem", map[string]*llx.RawData{
			"__id":    llx.StringData(fmt.Sprintf("solaris.zone.filesystem/%s/%d", z.Name.Data, i)),
			"dir":     llx.StringData(f.Dir),
			"special": llx.StringData(f.Special),
			"raw":     llx.StringData(f.Raw),
			"type":    llx.StringData(f.Type),
			"options": llx.ArrayData(stringsToAny(f.Options), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (z *mqlSolarisZone) createDevices(devices []solariszone.Device) ([]any, error) {
	res := make([]any, 0, len(devices))
	for i, d := range devices {
		o, err := CreateResource(z.MqlRuntime, "solaris.zone.device", map[string]*llx.RawData{
			"__id":           llx.StringData(fmt.Sprintf("solaris.zone.device/%s/%d", z.Name.Data, i)),
			"match":          llx.StringData(d.Match),
			"allowPartition": llx.BoolData(d.AllowPartition),
			"allowRawIo":     llx.BoolData(d.AllowRawIO),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

// Every field below comes from loadConfig, which sets it; the value returned
// here is never read when loadConfig succeeds.

func (z *mqlSolarisZone) autoboot() (bool, error) {
	_, err := z.loadConfig()
	return false, err
}

func (z *mqlSolarisZone) bootargs() (string, error) {
	_, err := z.loadConfig()
	return "", err
}

func (z *mqlSolarisZone) limitpriv() ([]any, error) {
	_, err := z.loadConfig()
	return nil, err
}

func (z *mqlSolarisZone) fileMacProfile() (string, error) {
	_, err := z.loadConfig()
	return "", err
}

func (z *mqlSolarisZone) fsAllowed() ([]any, error) {
	_, err := z.loadConfig()
	return nil, err
}

func (z *mqlSolarisZone) schedulingClass() (string, error) {
	_, err := z.loadConfig()
	return "", err
}

func (z *mqlSolarisZone) hostid() (string, error) {
	_, err := z.loadConfig()
	return "", err
}

func (z *mqlSolarisZone) networks() ([]any, error) {
	_, err := z.loadConfig()
	return nil, err
}

func (z *mqlSolarisZone) filesystems() ([]any, error) {
	_, err := z.loadConfig()
	return nil, err
}

func (z *mqlSolarisZone) devices() ([]any, error) {
	_, err := z.loadConfig()
	return nil, err
}

func (z *mqlSolarisZone) memoryCapBytes() (int64, error) {
	_, err := z.loadConfig()
	return 0, err
}

func (z *mqlSolarisZone) swapCapBytes() (int64, error) {
	_, err := z.loadConfig()
	return 0, err
}

func (z *mqlSolarisZone) lockedMemoryCapBytes() (int64, error) {
	_, err := z.loadConfig()
	return 0, err
}

func (z *mqlSolarisZone) cpuCap() (float64, error) {
	_, err := z.loadConfig()
	return 0, err
}

func (z *mqlSolarisZone) dedicatedCpus() (string, error) {
	_, err := z.loadConfig()
	return "", err
}

func (z *mqlSolarisZone) maxLwps() (int64, error) {
	_, err := z.loadConfig()
	return 0, err
}

func (z *mqlSolarisZone) maxProcesses() (int64, error) {
	_, err := z.loadConfig()
	return 0, err
}

// datasets resolves the delegated datasets against the zfs dataset list,
// which is read once and shared with zfs.datasets.
func (z *mqlSolarisZone) datasets() ([]any, error) {
	s, err := z.loadConfig()
	if err != nil {
		return nil, err
	}
	names := s.Datasets
	if len(names) == 0 {
		return []any{}, nil
	}

	obj, err := CreateResource(z.MqlRuntime, "zfs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := obj.(*mqlZfs).GetDatasets()
	if all.Error != nil {
		return nil, all.Error
	}
	byName := make(map[string]*mqlZfsDataset, len(all.Data))
	for _, d := range all.Data {
		ds := d.(*mqlZfsDataset)
		byName[ds.Name.Data] = ds
	}

	res := make([]any, 0, len(names))
	for _, n := range names {
		ds, ok := byName[n]
		if !ok {
			return nil, llx.NotFound(fmt.Errorf("zone %s delegates zfs dataset %s, which does not exist", z.Name.Data, n))
		}
		res = append(res, ds)
	}
	return res, nil
}
