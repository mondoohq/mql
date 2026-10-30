// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	nasclient "github.com/alibabacloud-go/nas-20170626/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAlicloudNas) id() (string, error) {
	return "alicloud.nas", nil
}

// nasEncrypted reports whether a NAS file system is encrypted at rest. The
// EncryptType field is 0 for no encryption, 1 for the NAS-managed service key,
// and 2 for a customer master key; anything non-zero means encrypted.
func nasEncrypted(encryptType *int32) bool {
	return encryptType != nil && *encryptType != 0
}

func (r *mqlAlicloudNas) fileSystems() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.NasClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		firstPage := true
		for {
			resp, err := client.DescribeFileSystems(&nasclient.DescribeFileSystemsRequest{
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil {
				if firstPage {
					// the region may not have NAS enabled or the credential may
					// lack access there; skip it rather than failing the scan
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil || resp.Body.FileSystems == nil {
				break
			}
			items := resp.Body.FileSystems.FileSystem
			for _, fs := range items {
				if fs == nil || fs.FileSystemId == nil {
					continue
				}
				mqlFs, err := newNasFileSystem(r.MqlRuntime, region, fs)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlFs)
			}
			if len(items) < int(pageSize) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// mqlAlicloudNasFileSystemInternal caches the KMS key id and the nested mount
// targets returned inline by DescribeFileSystems, so mountTargets() needs no
// extra API call.
type mqlAlicloudNasFileSystemInternal struct {
	cacheKmsKeyId     string
	cacheMountTargets []*nasclient.DescribeFileSystemsResponseBodyFileSystemsFileSystemMountTargetsMountTarget
}

func newNasFileSystem(runtime *plugin.Runtime, region string, fs *nasclient.DescribeFileSystemsResponseBodyFileSystemsFileSystem) (*mqlAlicloudNasFileSystem, error) {
	encrypted := nasEncrypted(fs.EncryptType)

	tags := map[string]any{}
	if fs.Tags != nil {
		for _, t := range fs.Tags.Tag {
			if t == nil || t.Key == nil {
				continue
			}
			tags[*t.Key] = tea.StringValue(t.Value)
		}
	}

	resource, err := CreateResource(runtime, "alicloud.nas.fileSystem", map[string]*llx.RawData{
		"__id":            llx.StringData(region + "/" + tea.StringValue(fs.FileSystemId)),
		"regionId":        llx.StringData(region),
		"fileSystemId":    llx.StringDataPtr(fs.FileSystemId),
		"fileSystemType":  llx.StringDataPtr(fs.FileSystemType),
		"protocolType":    llx.StringDataPtr(fs.ProtocolType),
		"storageType":     llx.StringDataPtr(fs.StorageType),
		"description":     llx.StringDataPtr(fs.Description),
		"zoneId":          llx.StringDataPtr(fs.ZoneId),
		"capacity":        llx.IntData(tea.Int64Value(fs.Capacity)),
		"meteredSize":     llx.IntData(tea.Int64Value(fs.MeteredSize)),
		"status":          llx.StringDataPtr(fs.Status),
		"chargeType":      llx.StringDataPtr(fs.ChargeType),
		"redundancyType":  llx.StringDataPtr(fs.RedundancyType),
		"encryptType":     llx.IntData(int64(tea.Int32Value(fs.EncryptType))),
		"encrypted":       llx.BoolData(encrypted),
		"resourceGroupId": llx.StringDataPtr(fs.ResourceGroupId),
		"createTime":      llx.TimeDataPtr(alicloudParseTime(fs.CreateTime)),
		"tags":            llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlFs := resource.(*mqlAlicloudNasFileSystem)
	mqlFs.cacheKmsKeyId = tea.StringValue(fs.KMSKeyId)
	if fs.MountTargets != nil {
		mqlFs.cacheMountTargets = fs.MountTargets.MountTarget
	}
	return mqlFs, nil
}

// initAlicloudNasFileSystem resolves a file system by id within a region,
// reusing an already-listed file system from the resource cache and otherwise
// fetching it via DescribeFileSystems filtered by id.
func initAlicloudNasFileSystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	fsID, err := requiredStringArg(args, "fileSystemId", "alicloud.nas.fileSystem")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.nas.fileSystem")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.nas.fileSystem\x00" + region + "/" + fsID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.NasClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeFileSystems(&nasclient.DescribeFileSystemsRequest{
		FileSystemId: new(fsID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.FileSystems != nil {
		for _, fs := range resp.Body.FileSystems.FileSystem {
			if fs == nil || fs.FileSystemId == nil || *fs.FileSystemId != fsID {
				continue
			}
			res, err := newNasFileSystem(runtime, region, fs)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.nas.fileSystem %q not found in region %q", fsID, region)
}

func (r *mqlAlicloudNasFileSystem) id() (string, error) {
	return r.RegionId.Data + "/" + r.FileSystemId.Data, nil
}

func (r *mqlAlicloudNasFileSystem) kmsKey() (*mqlAlicloudKmsKey, error) {
	if r.cacheKmsKeyId == "" {
		r.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveKmsKey(r.MqlRuntime, r.RegionId.Data, r.cacheKmsKeyId)
}

func (r *mqlAlicloudNasFileSystem) mountTargets() ([]any, error) {
	region := r.RegionId.Data
	fsID := r.FileSystemId.Data
	res := []any{}
	for _, mt := range r.cacheMountTargets {
		if mt == nil || mt.MountTargetDomain == nil {
			continue
		}
		mqlMt, err := newNasMountTarget(r.MqlRuntime, region, fsID, tea.StringValue(mt.MountTargetDomain),
			tea.StringValue(mt.Status), tea.StringValue(mt.NetworkType), tea.StringValue(mt.AccessGroupName),
			tea.StringValue(mt.VpcId), tea.StringValue(mt.VswId))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlMt)
	}
	return res, nil
}

// mqlAlicloudNasMountTargetInternal caches the VPC and vSwitch ids for the typed
// vpc()/vswitch() references.
type mqlAlicloudNasMountTargetInternal struct {
	cacheVpcId     string
	cacheVswitchId string
}

func newNasMountTarget(runtime *plugin.Runtime, region, fsID, domain, status, networkType, accessGroupName, vpcId, vswitchId string) (*mqlAlicloudNasMountTarget, error) {
	resource, err := CreateResource(runtime, "alicloud.nas.mountTarget", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + domain),
		"regionId":          llx.StringData(region),
		"fileSystemId":      llx.StringData(fsID),
		"mountTargetDomain": llx.StringData(domain),
		"status":            llx.StringData(status),
		"networkType":       llx.StringData(networkType),
		"accessGroupName":   llx.StringData(accessGroupName),
	})
	if err != nil {
		return nil, err
	}
	mqlMt := resource.(*mqlAlicloudNasMountTarget)
	mqlMt.cacheVpcId = vpcId
	mqlMt.cacheVswitchId = vswitchId
	return mqlMt, nil
}

func (r *mqlAlicloudNasMountTarget) id() (string, error) {
	return r.RegionId.Data + "/" + r.MountTargetDomain.Data, nil
}

func (r *mqlAlicloudNasMountTarget) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.RegionId.Data, r.cacheVpcId)
}

func (r *mqlAlicloudNasMountTarget) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchId == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.RegionId.Data, r.cacheVswitchId)
}

// fileSystem resolves the file system the mount target belongs to. A mount
// target cannot outlive its file system, so a failure to read it is a real
// error. The file system is already in the resource cache whenever the mount
// target was reached through it, which the file system init consults before
// calling the API.
func (r *mqlAlicloudNasMountTarget) fileSystem() (*mqlAlicloudNasFileSystem, error) {
	fsID := r.FileSystemId.Data
	if fsID == "" {
		r.FileSystem.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.nas.fileSystem", map[string]*llx.RawData{
		"fileSystemId": llx.StringData(fsID),
		"regionId":     llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudNasFileSystem), nil
}

func (r *mqlAlicloudNasMountTarget) accessGroup() (*mqlAlicloudNasAccessGroup, error) {
	name := r.AccessGroupName.Data
	if name == "" {
		r.AccessGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveNasAccessGroup(r.MqlRuntime, r.RegionId.Data, name)
}

func (r *mqlAlicloudNas) accessGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.NasClient(region)
		if err != nil {
			return nil, err
		}
		pageNumber := int32(1)
		pageSize := int32(100)
		firstPage := true
		for {
			resp, err := client.DescribeAccessGroups(&nasclient.DescribeAccessGroupsRequest{
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil {
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil || resp.Body.AccessGroups == nil {
				break
			}
			items := resp.Body.AccessGroups.AccessGroup
			for _, ag := range items {
				if ag == nil || ag.AccessGroupName == nil {
					continue
				}
				mqlAg, err := newNasAccessGroup(r.MqlRuntime, region, ag)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlAg)
			}
			if len(items) < int(pageSize) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

func newNasAccessGroup(runtime *plugin.Runtime, region string, ag *nasclient.DescribeAccessGroupsResponseBodyAccessGroupsAccessGroup) (*mqlAlicloudNasAccessGroup, error) {
	resource, err := CreateResource(runtime, "alicloud.nas.accessGroup", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + tea.StringValue(ag.AccessGroupName)),
		"regionId":         llx.StringData(region),
		"accessGroupName":  llx.StringDataPtr(ag.AccessGroupName),
		"accessGroupType":  llx.StringDataPtr(ag.AccessGroupType),
		"fileSystemType":   llx.StringDataPtr(ag.FileSystemType),
		"ruleCount":        llx.IntData(int64(tea.Int32Value(ag.RuleCount))),
		"mountTargetCount": llx.IntData(int64(tea.Int32Value(ag.MountTargetCount))),
		"description":      llx.StringDataPtr(ag.Description),
		"createTime":       llx.TimeDataPtr(alicloudParseTime(ag.CreateTime)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudNasAccessGroup), nil
}

// resolveNasAccessGroup returns the typed NAS access group for a name within a
// region, or (nil, nil) when name is empty. Following the provider's resolver
// convention, callers must set StateIsNull on the field before invoking it with
// a possibly-empty name (as mountTarget.accessGroup does), so a null result is
// reported rather than causing a re-fetch or panic.
func resolveNasAccessGroup(runtime *plugin.Runtime, region, name string) (*mqlAlicloudNasAccessGroup, error) {
	if name == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.nas.accessGroup", map[string]*llx.RawData{
		"accessGroupName": llx.StringData(name),
		"regionId":        llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudNasAccessGroup), nil
}

func initAlicloudNasAccessGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	name, err := requiredStringArg(args, "accessGroupName", "alicloud.nas.accessGroup")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.nas.accessGroup")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.nas.accessGroup\x00" + region + "/" + name); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.NasClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeAccessGroups(&nasclient.DescribeAccessGroupsRequest{
		AccessGroupName: new(name),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.AccessGroups != nil {
		for _, ag := range resp.Body.AccessGroups.AccessGroup {
			if ag == nil || ag.AccessGroupName == nil || *ag.AccessGroupName != name {
				continue
			}
			res, err := newNasAccessGroup(runtime, region, ag)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.nas.accessGroup %q not found in region %q", name, region)
}

func (r *mqlAlicloudNasAccessGroup) id() (string, error) {
	return r.RegionId.Data + "/" + r.AccessGroupName.Data, nil
}

func (r *mqlAlicloudNasAccessGroup) accessRules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	region := r.RegionId.Data
	groupName := r.AccessGroupName.Data
	client, err := conn.NasClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.DescribeAccessRules(&nasclient.DescribeAccessRulesRequest{
			AccessGroupName: new(groupName),
			PageNumber:      new(pageNumber),
			PageSize:        new(pageSize),
		})
		if err != nil {
			// the access group exists (it was listed/resolved), so an error
			// listing its rules is a real failure
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.AccessRules == nil {
			break
		}
		items := resp.Body.AccessRules.AccessRule
		for _, ar := range items {
			if ar == nil || ar.AccessRuleId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.nas.accessRule", map[string]*llx.RawData{
				"__id":             llx.StringData(region + "/" + groupName + "/" + tea.StringValue(ar.AccessRuleId)),
				"regionId":         llx.StringData(region),
				"accessGroupName":  llx.StringData(groupName),
				"accessRuleId":     llx.StringDataPtr(ar.AccessRuleId),
				"sourceCidrIp":     llx.StringDataPtr(ar.SourceCidrIp),
				"ipv6SourceCidrIp": llx.StringDataPtr(ar.Ipv6SourceCidrIp),
				"rwAccess":         llx.StringDataPtr(ar.RWAccess),
				"userAccess":       llx.StringDataPtr(ar.UserAccess),
				"priority":         llx.IntData(int64(tea.Int32Value(ar.Priority))),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
		if len(items) < int(pageSize) {
			break
		}
		pageNumber++
	}
	return res, nil
}

func (r *mqlAlicloudNasAccessRule) id() (string, error) {
	return r.RegionId.Data + "/" + r.AccessGroupName.Data + "/" + r.AccessRuleId.Data, nil
}
