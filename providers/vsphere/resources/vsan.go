// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	vimtypes "github.com/vmware/govmomi/vim25/types"
	vsantypes "github.com/vmware/govmomi/vsan/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/types"
)

// mqlVsphereClusterVsanInternal caches the encryption key-provider id (so the
// kmsProvider() accessor can resolve the typed vsphere.kmsCluster lazily) and
// the cluster reference (so health() can run its own — potentially slow and
// separately-privileged — object-health query only when requested).
type mqlVsphereClusterVsanInternal struct {
	cacheKmsProviderId string
	cacheClusterRef    vimtypes.ManagedObjectReference
}

// vsan returns the cluster's vSAN service configuration, or null when vSAN is
// not enabled on the cluster. The data comes from the vSAN management endpoint
// (VsanClusterGetConfig), with overall object health pulled from
// VsanQueryObjectIdentities.
func (v *mqlVsphereCluster) vsan() (*mqlVsphereClusterVsan, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	// v.Moid.Data is the ManagedObjectReference.Encode() form (type and
	// URL-escaped value joined with "-"); FromString is not its inverse, so
	// decode it explicitly. See decodeMoRef in tags.go.
	clusterRef, ok := decodeMoRef(v.Moid.Data)
	if !ok {
		return nil, fmt.Errorf("invalid cluster moid: %q", v.Moid.Data)
	}

	vc, err := conn.VsanClient(ctx)
	if err != nil {
		return nil, err
	}

	cfg, err := vc.VsanClusterGetConfig(ctx, clusterRef)
	if err != nil {
		return nil, err
	}
	// vSAN reports Enabled == nil/false when the service is off for the cluster.
	if cfg == nil || cfg.Enabled == nil || !*cfg.Enabled {
		v.Vsan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"__id":                       llx.StringData(v.Moid.Data + "/vsan"),
		"uuid":                       llx.StringData(vsanClusterUuid(cfg)),
		"esaEnabled":                 llx.BoolData(boolValue(cfg.VsanEsaEnabled)),
		"checksumEnabled":            llx.BoolData(vsanChecksumEnabled(cfg)),
		"dedupEnabled":               llx.BoolData(false),
		"compressionEnabled":         llx.BoolData(false),
		"encryptionEnabled":          llx.BoolData(false),
		"kekId":                      llx.StringData(""),
		"eraseDisksBeforeUse":        llx.BoolData(false),
		"inTransitEncryptionEnabled": llx.BoolData(false),
		"rekeyIntervalMinutes":       llx.IntData(0),
		"fileServiceEnabled":         llx.BoolData(false),
		"perfServiceEnabled":         llx.BoolData(false),
	}

	if de := cfg.DataEfficiencyConfig; de != nil {
		args["dedupEnabled"] = llx.BoolData(de.DedupEnabled)
		args["compressionEnabled"] = llx.BoolData(boolValue(de.CompressionEnabled))
	}

	kmsProviderId := ""
	if enc := cfg.DataEncryptionConfig; enc != nil {
		args["encryptionEnabled"] = llx.BoolData(enc.EncryptionEnabled)
		args["kekId"] = llx.StringData(enc.KekId)
		args["eraseDisksBeforeUse"] = llx.BoolData(boolValue(enc.EraseDisksBeforeUse))
		if enc.KmsProviderId != nil {
			kmsProviderId = enc.KmsProviderId.Id
		}
	}

	if dit := cfg.DataInTransitEncryptionConfig; dit != nil {
		args["inTransitEncryptionEnabled"] = llx.BoolData(boolValue(dit.Enabled))
		args["rekeyIntervalMinutes"] = llx.IntData(int64(dit.RekeyInterval))
	}

	if fs := cfg.FileServiceConfig; fs != nil {
		args["fileServiceEnabled"] = llx.BoolData(fs.Enabled)
	}

	if perf := cfg.PerfsvcConfig; perf != nil {
		args["perfServiceEnabled"] = llx.BoolData(perf.Enabled)
	}

	res, err := CreateResource(v.MqlRuntime, "vsphere.cluster.vsan", args)
	if err != nil {
		return nil, err
	}
	mqlVsan := res.(*mqlVsphereClusterVsan)
	mqlVsan.cacheKmsProviderId = kmsProviderId
	mqlVsan.cacheClusterRef = clusterRef
	return mqlVsan, nil
}

// health returns an overall vSAN object-health summary, or null when vCenter
// reports no health data for the cluster. It runs its own
// VsanQueryObjectIdentities call, kept out of the base vsan() build so that
// querying only the encryption/efficiency scalars doesn't pay for it. Genuine
// query failures (network, auth) are propagated rather than masked as null so
// they're distinguishable from a cluster that simply has no health data.
func (v *mqlVsphereClusterVsan) health() (map[string]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	vc, err := conn.VsanClient(ctx)
	if err != nil {
		return nil, err
	}

	identities, err := vc.VsanQueryObjectIdentities(ctx, v.cacheClusterRef)
	if err != nil {
		return nil, err
	}
	if identities == nil || identities.Health == nil {
		v.Health.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	h := identities.Health
	out := map[string]any{
		"objectVersionCompliance": boolValue(h.ObjectVersionCompliance),
		"objectsRelayoutBytes":    h.ObjectsRelayoutBytes,
	}
	if details, err := convert.JsonToDictSlice(h.ObjectHealthDetail); err == nil && len(details) > 0 {
		out["objectHealthDetail"] = details
	}
	return out, nil
}

// kmsProvider resolves the typed vsphere.kmsCluster backing data-at-rest
// encryption via the kmsClusters map on the cached inventory; null when
// encryption is disabled or the provider isn't in the registered list.
func (v *mqlVsphereClusterVsan) kmsProvider() (*mqlVsphereKmsCluster, error) {
	if v.cacheKmsProviderId == "" {
		v.KmsProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if cluster, ok := inv.kmsClusters[v.cacheKmsProviderId]; ok {
		return cluster, nil
	}
	v.KmsProvider.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// mqlVsphereHostVsanInternal caches the host's claimed disk groups so the
// diskGroups() accessor can build typed sub-resources without re-fetching the
// HostVsanSystem managed object. cacheHostMoid scopes each disk group's __id to
// its host so a cache-disk UUID seen on two hosts can't collide in the cache.
type mqlVsphereHostVsanInternal struct {
	cacheHostMoid     string
	cacheDiskMappings []vimtypes.VsanHostDiskMapping
}

// vsan returns the host's vSAN configuration, or null when the host does not
// participate in vSAN. The configuration is read from the host's
// HostVsanSystem managed object (ConfigManager.vsanSystem).
func (v *mqlVsphereHost) vsan() (*mqlVsphereHostVsan, error) {
	if v.host == nil || v.host.ConfigManager.VsanSystem == nil {
		v.Vsan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	vsanSystem := object.NewHostVsanSystem(conn.Client().Client, *v.host.ConfigManager.VsanSystem)
	var props mo.HostVsanSystem
	if err := vsanSystem.Properties(ctx, vsanSystem.Reference(), []string{"config"}, &props); err != nil {
		return nil, err
	}
	config := props.Config
	if config.Enabled == nil || !*config.Enabled {
		v.Vsan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	autoClaim := false
	checksum := false
	var diskMappings []vimtypes.VsanHostDiskMapping
	if si := config.StorageInfo; si != nil {
		autoClaim = boolValue(si.AutoClaimStorage)
		checksum = boolValue(si.ChecksumEnabled)
		diskMappings = si.DiskMapping
	}

	res, err := CreateResource(v.MqlRuntime, "vsphere.host.vsan", map[string]*llx.RawData{
		"__id":             llx.StringData(v.Moid.Data + "/vsan"),
		"enabled":          llx.BoolData(true),
		"autoClaimStorage": llx.BoolData(autoClaim),
		"checksumEnabled":  llx.BoolData(checksum),
	})
	if err != nil {
		return nil, err
	}
	mqlVsan := res.(*mqlVsphereHostVsan)
	mqlVsan.cacheHostMoid = v.Moid.Data
	mqlVsan.cacheDiskMappings = diskMappings
	return mqlVsan, nil
}

// diskGroups builds one vsphere.host.vsan.diskGroup per claimed disk group. The
// __id is host-scoped (<hostMoid>/vsanDiskGroup/<cacheDiskUuid>) so the same
// cache-disk UUID appearing on two hosts can't collide in the resource cache.
func (v *mqlVsphereHostVsan) diskGroups() ([]any, error) {
	mqlDiskGroups := make([]any, 0, len(v.cacheDiskMappings))
	for i, dm := range v.cacheDiskMappings {
		capacityDisks := make([]any, 0, len(dm.NonSsd))
		var capacityBytes int64
		for _, disk := range dm.NonSsd {
			capacityDisks = append(capacityDisks, scsiDiskName(disk))
			capacityBytes += scsiDiskCapacityBytes(disk)
		}

		// The cache SSD UUID is the natural key, but it can be empty on
		// all-flash/ESA topologies with no dedicated cache disk; fall back to
		// the mapping index so disk groups don't collide on one cache __id.
		dgKey := dm.Ssd.Uuid
		if dgKey == "" {
			dgKey = "dg" + strconv.Itoa(i)
		}
		res, err := CreateResource(v.MqlRuntime, "vsphere.host.vsan.diskGroup", map[string]*llx.RawData{
			"__id":              llx.StringData(v.cacheHostMoid + "/vsanDiskGroup/" + dgKey),
			"cacheDiskUuid":     llx.StringData(dm.Ssd.Uuid),
			"cacheDisk":         llx.StringData(scsiDiskName(dm.Ssd)),
			"capacityDisks":     llx.ArrayData(capacityDisks, types.String),
			"capacityDiskCount": llx.IntData(int64(len(dm.NonSsd))),
			"capacityBytes":     llx.IntData(capacityBytes),
		})
		if err != nil {
			return nil, err
		}
		mqlDiskGroups = append(mqlDiskGroups, res)
	}
	return mqlDiskGroups, nil
}

// scsiDiskName prefers the canonical name (e.g. "naa.…"), falling back to the
// display name and finally the device UUID.
func scsiDiskName(disk vimtypes.HostScsiDisk) string {
	if disk.CanonicalName != "" {
		return disk.CanonicalName
	}
	if disk.DisplayName != "" {
		return disk.DisplayName
	}
	return disk.Uuid
}

// scsiDiskCapacityBytes converts the LBA block geometry into a byte count.
// Some device types (virtual-flash, pass-through) can report an unset or
// partial geometry; treat any non-positive block count or size as unknown
// capacity (0) rather than letting a stray negative produce a bogus total.
func scsiDiskCapacityBytes(disk vimtypes.HostScsiDisk) int64 {
	if disk.Capacity.Block <= 0 || disk.Capacity.BlockSize <= 0 {
		return 0
	}
	return disk.Capacity.Block * int64(disk.Capacity.BlockSize)
}

func boolValue(b *bool) bool {
	return b != nil && *b
}

// vsanClusterUuid pulls the vSAN cluster UUID from the host-default config block.
func vsanClusterUuid(cfg *vsantypes.VsanConfigInfoEx) string {
	if cfg.DefaultConfig != nil {
		return cfg.DefaultConfig.Uuid
	}
	return ""
}

// vsanChecksumEnabled reports cluster-default checksum enforcement.
func vsanChecksumEnabled(cfg *vsantypes.VsanConfigInfoEx) bool {
	if cfg.DefaultConfig != nil {
		return boolValue(cfg.DefaultConfig.ChecksumEnabled)
	}
	return false
}
