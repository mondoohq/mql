// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	clustermgmtconfig "github.com/nutanix/ntnx-api-golang-clients/clustermgmt-go-client/v4/models/clustermgmt/v4/config"
	volconfig "github.com/nutanix/ntnx-api-golang-clients/volumes-go-client/v4/models/volumes/v4/config"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nutanix/connection"
	"go.mondoo.com/mql/types"
)

// ---------------------------------------------------------------------------
// storage containers
// ---------------------------------------------------------------------------

func listStorageContainers(conn *connection.NutanixConnection) ([]clustermgmtconfig.StorageContainer, error) {
	api := conn.StorageContainersApi()
	limit := pageSize
	all := []clustermgmtconfig.StorageContainer{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.CmgMu(), func() (*clustermgmtconfig.ListStorageContainersApiResponse, error) {
			return api.ListStorageContainers(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]clustermgmtconfig.StorageContainer)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListStorageContainers", data)
		}
		all = append(all, items...)
		if len(items) < limit {
			break
		}
	}
	return all, nil
}

func newMqlStorageContainer(runtime *plugin.Runtime, c *clustermgmtconfig.StorageContainer) (*mqlNutanixStorageContainer, error) {
	// ExtId is the container's stable identity and becomes the resource __id.
	// The API can return a container without one (e.g. system/partially
	// provisioned containers); such a container cannot be cached or
	// cross-referenced, so skip it rather than fail the whole listing.
	if c.ExtId == nil {
		return nil, nil
	}
	onDiskDedup := ""
	if c.OnDiskDedup != nil {
		onDiskDedup = c.OnDiskDedup.GetName()
	}
	cacheDedup := ""
	if c.CacheDeduplication != nil {
		cacheDedup = c.CacheDeduplication.GetName()
	}
	erasureCode := ""
	if c.ErasureCode != nil {
		erasureCode = c.ErasureCode.GetName()
	}
	nfsWhitelist := []any{}
	for i := range c.NfsWhitelistAddress {
		nfsWhitelist = append(nfsWhitelist, clusterIPOrFqdnToString(&c.NfsWhitelistAddress[i]))
	}

	res, err := CreateResource(runtime, "nutanix.storage.container", map[string]*llx.RawData{
		"__id":                                 llx.StringDataPtr(c.ExtId),
		"id":                                   llx.StringDataPtr(c.ExtId),
		"tenantId":                             llx.StringDataPtr(c.TenantId),
		"name":                                 llx.StringDataPtr(c.Name),
		"maxCapacityBytes":                     llx.IntData(derefInt64(c.MaxCapacityBytes)),
		"logicalAdvertisedCapacityBytes":       llx.IntData(derefInt64(c.LogicalAdvertisedCapacityBytes)),
		"logicalExplicitReservedCapacityBytes": llx.IntData(derefInt64(c.LogicalExplicitReservedCapacityBytes)),
		"logicalImplicitReservedCapacityBytes": llx.IntData(derefInt64(c.LogicalImplicitReservedCapacityBytes)),
		"isCompressionEnabled":                 llx.BoolData(derefBool(c.IsCompressionEnabled)),
		"compressionDelaySecs":                 llx.IntData(derefInt(c.CompressionDelaySecs)),
		"onDiskDedup":                          llx.StringData(onDiskDedup),
		"cacheDeduplication":                   llx.StringData(cacheDedup),
		"erasureCode":                          llx.StringData(erasureCode),
		"isInlineEcEnabled":                    llx.BoolData(derefBool(c.IsInlineEcEnabled)),
		"replicationFactor":                    llx.IntData(derefInt(c.ReplicationFactor)),
		"isEncrypted":                          llx.BoolData(derefBool(c.IsEncrypted)),
		"isSoftwareEncryptionEnabled":          llx.BoolData(derefBool(c.IsSoftwareEncryptionEnabled)),
		"nfsWhitelistAddresses":                llx.ArrayData(nfsWhitelist, types.String),
		"isNfsWhitelistInherited":              llx.BoolData(derefBool(c.IsNfsWhitelistInherited)),
		// The v4.0 API does not report whether a container is shared across clusters.
		"isInternal":         llx.BoolData(derefBool(c.IsInternal)),
		"isMarkedForRemoval": llx.BoolData(derefBool(c.IsMarkedForRemoval)),
		"storagePoolId":      llx.StringDataPtr(c.StoragePoolExtId),
	})
	if err != nil {
		return nil, err
	}
	mqlContainer := res.(*mqlNutanixStorageContainer)
	if c.ClusterExtId != nil {
		mqlContainer.cacheClusterId = *c.ClusterExtId
	}
	if c.OwnerExtId != nil {
		mqlContainer.cacheOwnerId = *c.OwnerExtId
	}
	if c.AffinityHostExtId != nil {
		mqlContainer.cacheAffinityHostId = *c.AffinityHostExtId
	}
	return mqlContainer, nil
}

func storageContainersForCluster(runtime *plugin.Runtime, conn *connection.NutanixConnection, clusterFilter string) ([]any, error) {
	containers, err := listStorageContainers(conn)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i := range containers {
		c := containers[i]
		if clusterFilter != "" && (c.ClusterExtId == nil || *c.ClusterExtId != clusterFilter) {
			continue
		}
		mqlContainer, err := newMqlStorageContainer(runtime, &c)
		if err != nil {
			return nil, err
		}
		if mqlContainer == nil {
			continue
		}
		res = append(res, mqlContainer)
	}
	return res, nil
}

func (a *mqlNutanix) storageContainers() ([]any, error) {
	conn := a.conn()
	return storageContainersForCluster(a.MqlRuntime, conn, conn.ClusterID())
}

func (a *mqlNutanixCluster) storageContainers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.NutanixConnection)
	return storageContainersForCluster(a.MqlRuntime, conn, a.clusterId)
}

type mqlNutanixStorageContainerInternal struct {
	cacheClusterId      string
	cacheOwnerId        string
	cacheAffinityHostId string
}

func (a *mqlNutanixStorageContainer) owner() (*mqlNutanixIamUser, error) {
	if a.cacheOwnerId == "" {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := userByID(a.MqlRuntime, a.cacheOwnerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixStorageContainer) cluster() (*mqlNutanixCluster, error) {
	if a.cacheClusterId == "" {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := clusterByID(a.MqlRuntime, a.cacheClusterId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixStorageContainer) affinityHost() (*mqlNutanixHost, error) {
	if a.cacheAffinityHostId == "" || a.cacheClusterId == "" {
		a.AffinityHost.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := hostByID(a.MqlRuntime, a.cacheClusterId, a.cacheAffinityHostId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.AffinityHost.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// volume groups
// ---------------------------------------------------------------------------

func (a *mqlNutanix) volumeGroups() ([]any, error) {
	conn := a.conn()
	api := conn.VolumeGroupsApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.VolMu(), func() (*volconfig.ListVolumeGroupsApiResponse, error) {
			return api.ListVolumeGroups(&p, &limit, nil, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]volconfig.VolumeGroup)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListVolumeGroups", data)
		}
		for i := range items {
			vg := items[i]
			if vg.ExtId == nil {
				continue
			}
			sharingStatus := ""
			if vg.SharingStatus != nil {
				sharingStatus = vg.SharingStatus.GetName()
			}
			usageType := ""
			if vg.UsageType != nil {
				usageType = vg.UsageType.GetName()
			}
			protocol := ""
			if vg.Protocol != nil {
				protocol = vg.Protocol.GetName()
			}
			attachmentType := ""
			if vg.AttachmentType != nil {
				attachmentType = vg.AttachmentType.GetName()
			}
			enabledAuth := ""
			if vg.EnabledAuthentications != nil {
				enabledAuth = vg.EnabledAuthentications.GetName()
			}
			mqlVg, err := CreateResource(a.MqlRuntime, "nutanix.storage.volumeGroup", map[string]*llx.RawData{
				"__id":                           llx.StringDataPtr(vg.ExtId),
				"id":                             llx.StringDataPtr(vg.ExtId),
				"tenantId":                       llx.StringDataPtr(vg.TenantId),
				"createdBy":                      llx.StringDataPtr(vg.CreatedBy),
				"name":                           llx.StringDataPtr(vg.Name),
				"description":                    llx.StringDataPtr(vg.Description),
				"sharingStatus":                  llx.StringData(sharingStatus),
				"usageType":                      llx.StringData(usageType),
				"protocol":                       llx.StringData(protocol),
				"attachmentType":                 llx.StringData(attachmentType),
				"enabledAuthentications":         llx.StringData(enabledAuth),
				"targetName":                     llx.StringDataPtr(vg.TargetName),
				"targetPrefix":                   llx.StringDataPtr(vg.TargetPrefix),
				"isHidden":                       llx.BoolData(derefBool(vg.IsHidden)),
				"shouldLoadBalanceVmAttachments": llx.BoolData(derefBool(vg.ShouldLoadBalanceVmAttachments)),
			})
			if err != nil {
				return nil, err
			}
			mv := mqlVg.(*mqlNutanixStorageVolumeGroup)
			if vg.ClusterReference != nil {
				mv.cacheClusterId = *vg.ClusterReference
			}
			mv.cacheDisks = vg.Disks
			res = append(res, mv)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}

type mqlNutanixStorageVolumeGroupInternal struct {
	cacheClusterId string
	cacheDisks     []volconfig.VolumeDisk
}

func (a *mqlNutanixStorageVolumeGroup) cluster() (*mqlNutanixCluster, error) {
	if a.cacheClusterId == "" {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := clusterByID(a.MqlRuntime, a.cacheClusterId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixStorageVolumeGroup) disks() ([]any, error) {
	res := []any{}
	for i := range a.cacheDisks {
		d := a.cacheDisks[i]
		// ExtId is the disk's stable identifier; fall back to a parent-qualified
		// synthetic key so disks without an ExtId don't collide in the cache.
		id := fmt.Sprintf("%s/disk/%d", a.Id.Data, derefInt(d.Index))
		if d.ExtId != nil && *d.ExtId != "" {
			id = *d.ExtId
		}
		mqlDisk, err := CreateResource(a.MqlRuntime, "nutanix.storage.volumeGroupDisk", map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"id":          llx.StringData(id),
			"description": llx.StringDataPtr(d.Description),
			"index":       llx.IntData(derefInt(d.Index)),
			"sizeBytes":   llx.IntData(derefInt64(d.DiskSizeBytes)),
		})
		if err != nil {
			return nil, err
		}
		mqlDiskRes := mqlDisk.(*mqlNutanixStorageVolumeGroupDisk)
		if d.StorageContainerId != nil {
			mqlDiskRes.cacheStorageContainerId = *d.StorageContainerId
		}
		res = append(res, mqlDiskRes)
	}
	return res, nil
}

type mqlNutanixStorageVolumeGroupDiskInternal struct {
	cacheStorageContainerId string
}

func (a *mqlNutanixStorageVolumeGroupDisk) storageContainer() (*mqlNutanixStorageContainer, error) {
	if a.cacheStorageContainerId == "" {
		a.StorageContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := storageContainerByID(a.MqlRuntime, a.cacheStorageContainerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.StorageContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func storageContainerByID(runtime *plugin.Runtime, containerID string) (*mqlNutanixStorageContainer, error) {
	if c, ok := cachedResource[*mqlNutanixStorageContainer](runtime, "nutanix.storage.container", containerID); ok {
		return c, nil
	}
	conn := runtime.Connection.(*connection.NutanixConnection)
	id := containerID
	resp, err := guard(conn.CmgMu(), func() (*clustermgmtconfig.GetStorageContainerApiResponse, error) {
		return conn.StorageContainersApi().GetStorageContainerById(&id)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		return nil, nil
	}
	container, ok := data.(clustermgmtconfig.StorageContainer)
	if !ok {
		return nil, nil
	}
	return newMqlStorageContainer(runtime, &container)
}
