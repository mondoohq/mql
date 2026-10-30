// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlVsphereVmDiskInternal struct {
	cacheDatastoreMoid string
	cacheKeyId         string
	cacheKeyProviderId string
}

func (v *mqlVsphereVm) snapshots() ([]any, error) {
	if v.vm == nil || v.vm.Snapshot == nil {
		return []any{}, nil
	}
	currentMoid := ""
	if v.vm.Snapshot.CurrentSnapshot != nil {
		currentMoid = v.vm.Snapshot.CurrentSnapshot.Encode()
	}
	vmMoid := v.Moid.Data

	out := []any{}
	var walk func(nodes []types.VirtualMachineSnapshotTree, parentMoid string) error
	walk = func(nodes []types.VirtualMachineSnapshotTree, parentMoid string) error {
		for _, n := range nodes {
			snapMoid := n.Snapshot.Encode()
			res, err := CreateResource(v.MqlRuntime, "vsphere.vm.snapshot", map[string]*llx.RawData{
				"__id":        llx.StringData(vmMoid + "/snapshot/" + snapMoid),
				"moid":        llx.StringData(snapMoid),
				"id":          llx.IntData(int64(n.Id)),
				"name":        llx.StringData(n.Name),
				"description": llx.StringData(n.Description),
				"createDate":  llx.TimeData(n.CreateTime),
				"powerState":  llx.StringData(string(n.State)),
				"quiesced":    llx.BoolData(n.Quiesced),
				"current":     llx.BoolData(snapMoid == currentMoid),
				"parentMoid":  llx.StringData(parentMoid),
			})
			if err != nil {
				return err
			}
			out = append(out, res)
			if err := walk(n.ChildSnapshotList, snapMoid); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(v.vm.Snapshot.RootSnapshotList, ""); err != nil {
		return nil, err
	}
	return out, nil
}

func (v *mqlVsphereVm) disks() ([]any, error) {
	if v.vm == nil || v.vm.Config == nil {
		return []any{}, nil
	}
	vmMoid := v.Moid.Data
	out := []any{}
	for _, dev := range v.vm.Config.Hardware.Device {
		disk, ok := dev.(*types.VirtualDisk)
		if !ok {
			continue
		}

		var (
			label                                       string
			backingType, fileName, diskMode, sharing    string
			uuid                                        string
			thinProvisioned, eagerlyScrub, writeThrough bool
			keyId, keyProviderId, datastoreMoid         string
		)
		if info := disk.DeviceInfo; info != nil {
			label = info.GetDescription().Label
		}

		switch b := disk.Backing.(type) {
		case *types.VirtualDiskFlatVer2BackingInfo:
			backingType = "flatVer2"
			fileName = b.FileName
			diskMode = b.DiskMode
			sharing = b.Sharing
			uuid = b.Uuid
			if b.ThinProvisioned != nil {
				thinProvisioned = *b.ThinProvisioned
			}
			if b.EagerlyScrub != nil {
				eagerlyScrub = *b.EagerlyScrub
			}
			if b.WriteThrough != nil {
				writeThrough = *b.WriteThrough
			}
			if b.KeyId != nil {
				keyId = b.KeyId.KeyId
				if b.KeyId.ProviderId != nil {
					keyProviderId = b.KeyId.ProviderId.Id
				}
			}
			if b.Datastore != nil {
				datastoreMoid = b.Datastore.Encode()
			}
		case *types.VirtualDiskRawDiskMappingVer1BackingInfo:
			backingType = "rdmV1"
			fileName = b.FileName
			diskMode = b.DiskMode
			sharing = b.Sharing
			uuid = b.Uuid
			if b.Datastore != nil {
				datastoreMoid = b.Datastore.Encode()
			}
		case *types.VirtualDiskSparseVer2BackingInfo:
			backingType = "sparseVer2"
			fileName = b.FileName
			diskMode = b.DiskMode
			uuid = b.Uuid
			if b.WriteThrough != nil {
				writeThrough = *b.WriteThrough
			}
			if b.KeyId != nil {
				keyId = b.KeyId.KeyId
				if b.KeyId.ProviderId != nil {
					keyProviderId = b.KeyId.ProviderId.Id
				}
			}
			if b.Datastore != nil {
				datastoreMoid = b.Datastore.Encode()
			}
		case *types.VirtualDiskSeSparseBackingInfo:
			backingType = "seSparse"
			fileName = b.FileName
			diskMode = b.DiskMode
			uuid = b.Uuid
			if b.KeyId != nil {
				keyId = b.KeyId.KeyId
				if b.KeyId.ProviderId != nil {
					keyProviderId = b.KeyId.ProviderId.Id
				}
			}
			if b.Datastore != nil {
				datastoreMoid = b.Datastore.Encode()
			}
		}

		capacityBytes := disk.CapacityInBytes
		if capacityBytes == 0 {
			capacityBytes = disk.CapacityInKB * 1024
		}

		res, err := CreateResource(v.MqlRuntime, "vsphere.vm.disk", map[string]*llx.RawData{
			"__id":            llx.StringData(vmMoid + "/disk/" + strconv.Itoa(int(disk.Key))),
			"key":             llx.IntData(int64(disk.Key)),
			"label":           llx.StringData(label),
			"backingType":     llx.StringData(backingType),
			"fileName":        llx.StringData(fileName),
			"capacityBytes":   llx.IntData(capacityBytes),
			"diskMode":        llx.StringData(diskMode),
			"thinProvisioned": llx.BoolData(thinProvisioned),
			"eagerlyScrub":    llx.BoolData(eagerlyScrub),
			"writeThrough":    llx.BoolData(writeThrough),
			"sharing":         llx.StringData(sharing),
			"uuid":            llx.StringData(uuid),
		})
		if err != nil {
			return nil, err
		}
		mqlDisk := res.(*mqlVsphereVmDisk)
		mqlDisk.cacheDatastoreMoid = datastoreMoid
		mqlDisk.cacheKeyId = keyId
		mqlDisk.cacheKeyProviderId = keyProviderId
		out = append(out, mqlDisk)
	}
	return out, nil
}

func (d *mqlVsphereVmDisk) datastore() (*mqlVsphereDatastore, error) {
	if d.cacheDatastoreMoid == "" {
		d.Datastore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	inv, err := loadVsphereInventory(d.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if ds, ok := inv.datastores[d.cacheDatastoreMoid]; ok {
		return ds, nil
	}
	d.Datastore.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (d *mqlVsphereVmDisk) encryptionKey() (*mqlVsphereEncryptionKey, error) {
	if d.cacheKeyId == "" {
		d.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id := d.cacheKeyId
	if d.cacheKeyProviderId != "" {
		id = d.cacheKeyProviderId + "/" + d.cacheKeyId
	}
	res, err := CreateResource(d.MqlRuntime, "vsphere.encryptionKey", map[string]*llx.RawData{
		"__id":       llx.StringData(id),
		"keyId":      llx.StringData(d.cacheKeyId),
		"providerId": llx.StringData(d.cacheKeyProviderId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVsphereEncryptionKey), nil
}

func (k *mqlVsphereEncryptionKey) kmsCluster() (*mqlVsphereKmsCluster, error) {
	providerId := k.ProviderId.Data
	if providerId == "" {
		k.KmsCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	inv, err := loadVsphereInventory(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if cluster, ok := inv.kmsClusters[providerId]; ok {
		return cluster, nil
	}
	k.KmsCluster.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
