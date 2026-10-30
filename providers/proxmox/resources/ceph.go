// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlProxmox) ceph() (*mqlProxmoxCeph, error) {
	res, err := CreateResource(r.MqlRuntime, "proxmox.ceph", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxCeph), nil
}

func (r *mqlProxmoxCeph) id() (string, error) {
	return "proxmox.ceph", nil
}

func cephConn(r *mqlProxmoxCeph) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

// ---------------------------------------------------------------------------
// Availability and status
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCeph) available() (bool, error) {
	available, _, err := cephConn(r).CephAvailable()
	return available, err
}

func (r *mqlProxmoxCeph) status() (any, error) {
	status, err := cephConn(r).GetCephStatus()
	if err != nil {
		return nil, err
	}
	if status == nil {
		return map[string]any{}, nil
	}
	return status, nil
}

// cephHealth pulls the `health` sub-object out of the status report. Ceph
// nests both the summary string and the active checks under it.
func (r *mqlProxmoxCeph) cephHealth() (map[string]any, error) {
	status, err := cephConn(r).GetCephStatus()
	if err != nil || status == nil {
		return nil, err
	}
	health, ok := status["health"].(map[string]any)
	if !ok {
		return nil, nil
	}
	return health, nil
}

func (r *mqlProxmoxCeph) healthStatus() (string, error) {
	health, err := r.cephHealth()
	if err != nil || health == nil {
		return "", err
	}
	s, _ := health["status"].(string)
	return s, nil
}

func (r *mqlProxmoxCeph) healthChecks() (any, error) {
	health, err := r.cephHealth()
	if err != nil || health == nil {
		return map[string]any{}, err
	}
	checks, ok := health["checks"].(map[string]any)
	if !ok {
		return map[string]any{}, nil
	}
	return checks, nil
}

func (r *mqlProxmoxCeph) nodeVersions() (any, error) {
	versions, err := cephConn(r).GetCephNodeVersions()
	if err != nil {
		return nil, err
	}
	if versions == nil {
		return map[string]any{}, nil
	}
	return versions, nil
}

// ---------------------------------------------------------------------------
// Daemons
// ---------------------------------------------------------------------------

// cephDaemonArgs maps the fields every daemon listing shares. Callers add the
// per-type fields (quorum for monitors, rank and fs_name for metadata
// servers) on top.
func cephDaemonArgs(resource string, d connection.CephDaemon) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData(resource + "/" + d.Name),
		"name":             llx.StringData(d.Name),
		"host":             llx.StringData(d.Host),
		"addr":             llx.StringData(d.Addr),
		"state":            llx.StringData(d.State),
		"service":          llx.BoolData(d.Service.Bool()),
		"directoryExists":  llx.BoolData(d.DirExists.Bool()),
		"cephVersion":      llx.StringData(d.CephVersion),
		"cephVersionShort": llx.StringData(d.CephVersionShort),
	}
}

func (r *mqlProxmoxCeph) monitors() ([]any, error) {
	mons, err := cephConn(r).GetCephMonitors()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(mons))
	for i, m := range mons {
		args := cephDaemonArgs("proxmox.ceph.monitor", m)
		args["quorum"] = llx.BoolData(m.Quorum.Bool())
		args["rank"] = llx.IntDataPtr(m.Rank)
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.monitor", args)
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCeph) managers() ([]any, error) {
	mgrs, err := cephConn(r).GetCephManagers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(mgrs))
	for i, m := range mgrs {
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.manager", cephDaemonArgs("proxmox.ceph.manager", m))
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCeph) metadataServers() ([]any, error) {
	servers, err := cephConn(r).GetCephMetadataServers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(servers))
	for i, m := range servers {
		args := cephDaemonArgs("proxmox.ceph.metadataServer", m)
		args["rank"] = llx.IntDataPtr(m.Rank)
		args["fsName"] = llx.StringData(m.FSName)
		args["standbyReplay"] = llx.BoolData(m.StandbyReplay.Bool())
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.metadataServer", args)
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCephMetadataServer) fileSystem() (*mqlProxmoxCephFilesystem, error) {
	if r.FsName.Data == "" {
		r.FileSystem.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.ceph.filesystem", map[string]*llx.RawData{
		"name": llx.StringData(r.FsName.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxCephFilesystem), nil
}

// ---------------------------------------------------------------------------
// OSDs
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCeph) osds() ([]any, error) {
	osds, err := cephConn(r).GetCephOSDs()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(osds))
	for i, o := range osds {
		args := map[string]*llx.RawData{
			"__id":             llx.StringData("proxmox.ceph.osd/" + strconv.Itoa(o.ID)),
			"id":               llx.IntData(int64(o.ID)),
			"name":             llx.StringData(o.Name),
			"host":             llx.StringData(o.Host),
			"status":           llx.StringData(o.Status),
			"deviceClass":      llx.StringData(o.DeviceClass),
			"crushWeight":      llx.FloatData(o.CrushWeight),
			"reweight":         llx.FloatData(o.Reweight),
			"totalSpace":       llx.IntData(o.TotalSpace),
			"bytesUsed":        llx.IntData(o.BytesUsed),
			"percentUsed":      llx.FloatData(o.PercentUsed),
			"objectStore":      llx.StringData(o.ObjectStore),
			"devices":          llx.StringData(o.Devices),
			"deviceIds":        llx.StringData(o.DeviceIDs),
			"devicePaths":      llx.StringData(o.DevicePaths),
			"frontAddress":     llx.StringData(o.FrontAddr),
			"backAddress":      llx.StringData(o.BackAddr),
			"dataPath":         llx.StringData(o.OSDData),
			"cephVersion":      llx.StringData(o.CephVersion),
			"cephVersionShort": llx.StringData(o.CephVersionShort),
			"cephRelease":      llx.StringData(o.CephRelease),
		}
		// `up` and `inCluster` stay null when the CRUSH tree reported no
		// state for the OSD. Defaulting either way would assert a health
		// claim the API never made.
		if o.Status != "" {
			up := o.Status == "up"
			args["up"] = llx.BoolData(up)
		} else {
			args["up"] = llx.NilData
		}
		if o.In != nil {
			args["inCluster"] = llx.BoolData(*o.In != 0)
		} else {
			args["inCluster"] = llx.NilData
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.osd", args)
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Pools, file systems, config
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCeph) pools() ([]any, error) {
	pools, err := cephConn(r).GetCephPools()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(pools))
	for i, p := range pools {
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.pool", cephPoolArgs(p))
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func cephPoolArgs(p connection.CephPool) map[string]*llx.RawData {
	applications := p.ApplicationMetadata
	if applications == nil {
		applications = map[string]any{}
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData("proxmox.ceph.pool/" + p.PoolName),
		"name":            llx.StringData(p.PoolName),
		"poolId":          llx.IntData(int64(p.Pool)),
		"type":            llx.StringData(p.Type),
		"size":            llx.IntData(int64(p.Size)),
		"minSize":         llx.IntData(int64(p.MinSize)),
		"pgNum":           llx.IntData(int64(p.PGNum)),
		"pgNumFinal":      llx.IntData(int64(p.PGNumFinal)),
		"pgNumMin":        llx.IntData(int64(p.PGNumMin)),
		"pgAutoscaleMode": llx.StringData(p.PGAutoscaleMode),
		"crushRuleId":     llx.IntData(int64(p.CrushRule)),
		"crushRuleName":   llx.StringData(p.CrushRuleName),
		"bytesUsed":       llx.IntData(p.BytesUsed),
		"percentUsed":     llx.FloatData(p.PercentUsed),
		"applications":    llx.DictData(applications),
	}
}

func (r *mqlProxmoxCeph) fileSystems() ([]any, error) {
	systems, err := cephConn(r).GetCephFileSystems()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(systems))
	for i, fs := range systems {
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.filesystem", cephFilesystemArgs(fs))
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func cephFilesystemArgs(fs connection.CephFS) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":         llx.StringData("proxmox.ceph.filesystem/" + fs.Name),
		"name":         llx.StringData(fs.Name),
		"metadataPool": llx.StringData(fs.MetadataPool),
		"dataPools":    llx.ArrayData(cephDataPools(fs), types.String),
	}
}

// cephDataPools normalizes the data-pool list. Older releases report only the
// first data pool through `data_pool`; newer ones return the full set in
// `data_pools`.
func cephDataPools(fs connection.CephFS) []any {
	if len(fs.DataPools) > 0 {
		out := make([]any, len(fs.DataPools))
		for i, p := range fs.DataPools {
			out[i] = p
		}
		return out
	}
	if fs.DataPool != "" {
		return []any{fs.DataPool}
	}
	return []any{}
}

// cephConfigEntryKey builds the cache key for a config-database entry.
// Section and name alone are not unique: Ceph allows the same key to be set
// more than once with different masks, for example a per-device-class
// override alongside a global default.
func cephConfigEntryKey(section, name, mask string) string {
	return fmt.Sprintf("proxmox.ceph.configEntry/%s/%s/%s", section, name, mask)
}

func (r *mqlProxmoxCeph) config() ([]any, error) {
	entries, err := cephConn(r).GetCephConfig()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(entries))
	for i, e := range entries {
		res, err := CreateResource(r.MqlRuntime, "proxmox.ceph.configEntry", map[string]*llx.RawData{
			"__id":               llx.StringData(cephConfigEntryKey(e.Section, e.Name, e.Mask)),
			"name":               llx.StringData(e.Name),
			"section":            llx.StringData(e.Section),
			"value":              llx.StringData(e.Value),
			"mask":               llx.StringData(e.Mask),
			"level":              llx.StringData(e.Level),
			"canUpdateAtRuntime": llx.BoolData(e.CanUpdateAtRuntime.Bool()),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCeph) crushRules() ([]any, error) {
	rules, err := cephConn(r).GetCephCrushRules()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(rules))
	for i, name := range rules {
		list[i] = name
	}
	return list, nil
}
