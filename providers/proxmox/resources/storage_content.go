// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// ---------------------------------------------------------------------------
// Storage volumes
// ---------------------------------------------------------------------------

type mqlProxmoxStorageVolumeInternal struct {
	// vmid is kept so the vm() and container() accessors can resolve the
	// owning guest without re-parsing the volume id.
	vmid int
}

func (r *mqlProxmoxStorage) volumes() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	info, err := storageInfoFor(conn, r.Id.Data)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return []any{}, nil
	}
	content, err := conn.ListStorageContent(*info)
	if err != nil {
		return nil, err
	}
	return storageVolumesToResources(r.MqlRuntime, content)
}

func (r *mqlProxmoxStorage) backups() ([]any, error) {
	volumes := r.GetVolumes()
	if volumes.Error != nil {
		return nil, volumes.Error
	}
	backups := make([]any, 0, len(volumes.Data))
	for _, v := range volumes.Data {
		vol, ok := v.(*mqlProxmoxStorageVolume)
		if !ok {
			continue
		}
		if vol.ContentType.Data == "backup" {
			backups = append(backups, vol)
		}
	}
	return backups, nil
}

// storageInfoFor looks up a storage's cluster configuration by id. The
// configuration carries the `shared` and `nodes` values that decide which
// nodes a volume listing has to visit.
func storageInfoFor(conn *connection.PveConnection, id string) (*connection.StorageInfo, error) {
	storages, err := conn.GetStorages()
	if err != nil {
		return nil, err
	}
	for i := range storages {
		if storages[i].Storage == id {
			return &storages[i], nil
		}
	}
	return nil, nil
}

func storageVolumesToResources(runtime *plugin.Runtime, content []connection.StorageContent) ([]any, error) {
	list := make([]any, 0, len(content))
	for _, v := range content {
		res, err := CreateResource(runtime, "proxmox.storage.volume", storageVolumeArgs(v))
		if err != nil {
			return nil, err
		}
		vol := res.(*mqlProxmoxStorageVolume)
		vol.vmid = v.VMID
		list = append(list, vol)
	}
	return list, nil
}

func storageVolumeArgs(v connection.StorageContent) map[string]*llx.RawData {
	verification := v.Verification
	if verification == nil {
		verification = map[string]any{}
	}
	args := map[string]*llx.RawData{
		// A local storage holds an independent copy per node, so the volume
		// id alone is not unique across the cluster.
		"__id":                  llx.StringData("proxmox.storage.volume/" + v.Node + "/" + v.VolID),
		"volid":                 llx.StringData(v.VolID),
		"storage":               llx.StringData(v.Storage),
		"node":                  llx.StringData(v.Node),
		"contentType":           llx.StringData(v.ContentType()),
		"format":                llx.StringData(v.Format),
		"size":                  llx.IntData(v.Size),
		"used":                  llx.IntData(v.Used),
		"vmid":                  llx.IntData(int64(v.VMID)),
		"encrypted":             llx.BoolData(v.Encrypted != ""),
		"encryptionFingerprint": llx.StringData(v.Encrypted),
		"protected":             llx.BoolData(v.Protected.Bool()),
		"verification":          llx.DictData(verification),
		"notes":                 llx.StringData(v.Notes),
		"parent":                llx.StringData(v.Parent),
	}
	// A missing ctime stays null rather than becoming the Unix epoch, which
	// would read as a backup written in 1970 and pass any recency check
	// phrased as "older than".
	if v.CTime > 0 {
		t := time.Unix(v.CTime, 0).UTC()
		args["createdAt"] = llx.TimeData(t)
	} else {
		args["createdAt"] = llx.NilData
	}
	return args
}

// vm resolves the virtual machine that owns this volume.
//
// A VMID identifies exactly one guest, but it may be a container, and backups
// outlive the guest they were taken from. Both cases have to report null, so
// membership is confirmed against the live guest list first: the resource
// inits create a resource from whatever args they were handed when a lookup
// misses, which would turn "this backup belongs to a container" into a
// virtual machine with every field unset.
func (r *mqlProxmoxStorageVolume) vm() (*mqlProxmoxVm, error) {
	if r.vmid == 0 {
		r.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	vms, err := conn.GetAllVMs()
	if err != nil {
		return nil, err
	}
	found := false
	for _, vm := range vms {
		if vm.VMID == r.vmid {
			found = true
			break
		}
	}
	if !found {
		r.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.vm", map[string]*llx.RawData{
		"id": llx.IntData(int64(r.vmid)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxVm), nil
}

// container resolves the container that owns this volume, using the same
// membership check as vm() and for the same reason.
func (r *mqlProxmoxStorageVolume) container() (*mqlProxmoxContainer, error) {
	if r.vmid == 0 {
		r.Container.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	containers, err := conn.GetAllContainers()
	if err != nil {
		return nil, err
	}
	found := false
	for _, ct := range containers {
		if ct.VMID == r.vmid {
			found = true
			break
		}
	}
	if !found {
		r.Container.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.container", map[string]*llx.RawData{
		"id": llx.IntData(int64(r.vmid)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxContainer), nil
}

// ---------------------------------------------------------------------------
// Per-guest backups
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVm) backups() ([]any, error) {
	return guestBackups(r.MqlRuntime, int(r.Id.Data))
}

func (r *mqlProxmoxVm) lastBackupAt() (*time.Time, error) {
	backups := r.GetBackups()
	if backups.Error != nil {
		return nil, backups.Error
	}
	return newestBackupTime(r.MqlRuntime, backups.Data, &r.LastBackupAt)
}

func (r *mqlProxmoxContainer) backups() ([]any, error) {
	return guestBackups(r.MqlRuntime, int(r.Id.Data))
}

func (r *mqlProxmoxContainer) lastBackupAt() (*time.Time, error) {
	backups := r.GetBackups()
	if backups.Error != nil {
		return nil, backups.Error
	}
	return newestBackupTime(r.MqlRuntime, backups.Data, &r.LastBackupAt)
}

// guestBackups returns a guest's backup archives, newest first. The
// underlying cluster sweep is memoized on the connection, so asking every
// guest costs one pass rather than one pass per guest.
func guestBackups(runtime *plugin.Runtime, vmid int) ([]any, error) {
	conn := runtime.Connection.(*connection.PveConnection)
	content, err := conn.GetBackupsForGuest(vmid)
	if err != nil {
		return nil, err
	}
	sorted := make([]connection.StorageContent, len(content))
	copy(sorted, content)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].CTime > sorted[j].CTime
	})
	return storageVolumesToResources(runtime, sorted)
}

// newestBackupTime reads the creation time off the first entry of an
// already-sorted backup list. A guest with no backups reports null, which is
// the honest answer: there is no date to give.
func newestBackupTime(runtime *plugin.Runtime, backups []any, field *plugin.TValue[*time.Time]) (*time.Time, error) {
	for _, b := range backups {
		vol, ok := b.(*mqlProxmoxStorageVolume)
		if !ok {
			continue
		}
		created := vol.GetCreatedAt()
		if created.Error != nil {
			return nil, created.Error
		}
		if created.Data != nil {
			return created.Data, nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
