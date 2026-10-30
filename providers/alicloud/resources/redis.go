// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	rkvclient "github.com/alibabacloud-go/r-kvstore-20150101/v8/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// redisParseTime converts an RFC3339 timestamp string (as returned by the
// ApsaraDB for Redis API) to a *time.Time, returning nil on a nil or
// unparseable value.
func redisParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// redisTagsToMap flattens the Redis instance tag list into a string map.
func redisTagsToMap(tags *rkvclient.DescribeInstancesResponseBodyInstancesKVStoreInstanceTags) map[string]any {
	res := map[string]any{}
	if tags == nil {
		return res
	}
	for _, t := range tags.Tag {
		if t == nil || t.Key == nil {
			continue
		}
		res[*t.Key] = tea.StringValue(t.Value)
	}
	return res
}

func (r *mqlAlicloudRedis) id() (string, error) {
	return "alicloud.redis", nil
}

// mqlAlicloudRedisInstanceInternal caches the region an instance was
// discovered in so the security-posture accessors can build a region-scoped
// client for the per-instance detail calls, and the native VPC/vSwitch ids so
// the typed accessors can resolve them.
type mqlAlicloudRedisInstanceInternal struct {
	redisAuditState
	region         string
	cacheRegion    string
	cacheVpcID     string
	cacheVswitchID string
}

func (r *mqlAlicloudRedis) instances() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.RedisClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(50)
		for {
			resp, err := client.DescribeInstances(&rkvclient.DescribeInstancesRequest{
				RegionId:   new(region),
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil {
				// Skip regions that reject the call (for example a region the
				// account has not activated the service in) rather than failing
				// the whole listing.
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.Instances == nil {
				break
			}

			for _, inst := range resp.Body.Instances.KVStoreInstance {
				if inst == nil || inst.InstanceId == nil {
					continue
				}

				mqlInst, err := newRedisInstance(r.MqlRuntime, region, inst)
				if err != nil {
					return nil, err
				}
				// DescribeInstances returns tags inline, so the filter costs
				// nothing beyond the listing already made
				if filteredOutByTags(conn, mqlInst.Tags.Data) {
					continue
				}
				res = append(res, mqlInst)
			}

			total := tea.Int32Value(resp.Body.TotalCount)
			if total == 0 || pageNumber*pageSize >= total {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// newRedisInstance builds a fully populated alicloud.redis.instance from a
// DescribeInstances list item within a region. It is shared by the instances
// list accessor and the by-id init so both produce identical resources.
func newRedisInstance(runtime *plugin.Runtime, region string, inst *rkvclient.DescribeInstancesResponseBodyInstancesKVStoreInstance) (*mqlAlicloudRedisInstance, error) {
	resource, err := CreateResource(runtime, "alicloud.redis.instance", map[string]*llx.RawData{
		"__id":             llx.StringDataPtr(inst.InstanceId),
		"instanceId":       llx.StringDataPtr(inst.InstanceId),
		"instanceName":     llx.StringDataPtr(inst.InstanceName),
		"instanceStatus":   llx.StringDataPtr(inst.InstanceStatus),
		"instanceType":     llx.StringDataPtr(inst.InstanceType),
		"instanceClass":    llx.StringDataPtr(inst.InstanceClass),
		"architectureType": llx.StringDataPtr(inst.ArchitectureType),
		"engineVersion":    llx.StringDataPtr(inst.EngineVersion),
		"regionId":         llx.StringDataPtr(inst.RegionId),
		"zoneId":           llx.StringDataPtr(inst.ZoneId),
		"secondaryZoneId":  llx.StringDataPtr(inst.SecondaryZoneId),
		"networkType":      llx.StringDataPtr(inst.NetworkType),
		"connectionDomain": llx.StringDataPtr(inst.ConnectionDomain),
		"port":             llx.IntDataPtr(inst.Port),
		"privateIp":        llx.StringDataPtr(inst.PrivateIp),
		"capacity":         llx.IntDataPtr(inst.Capacity),
		"bandwidth":        llx.IntDataPtr(inst.Bandwidth),
		"qps":              llx.IntDataPtr(inst.QPS),
		"connections":      llx.IntDataPtr(inst.Connections),
		"chargeType":       llx.StringDataPtr(inst.ChargeType),
		"nodeType":         llx.StringDataPtr(inst.NodeType),
		"packageType":      llx.StringDataPtr(inst.PackageType),
		"editionType":      llx.StringDataPtr(inst.EditionType),
		"resourceGroupId":  llx.StringDataPtr(inst.ResourceGroupId),
		"createTime":       llx.TimeDataPtr(redisParseTime(inst.CreateTime)),
		"endTime":          llx.TimeDataPtr(redisParseTime(inst.EndTime)),
		"tags":             llx.MapData(redisTagsToMap(inst.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlInst := resource.(*mqlAlicloudRedisInstance)
	mqlInst.region = region
	mqlInst.cacheRegion = region
	mqlInst.cacheVpcID = tea.StringValue(inst.VpcId)
	mqlInst.cacheVswitchID = tea.StringValue(inst.VSwitchId)
	return mqlInst, nil
}

// initAlicloudRedisInstance resolves an ApsaraDB for Redis instance by its
// native instance id within a region, reusing an already-listed instance from
// the resource cache. It also backs the discovered redis-instance asset, which
// scopes the connection to one instance.
func initAlicloudRedisInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered Redis instance asset, resolve the instance the asset is
	// scoped to
	args = scopedInitArgs(runtime, args, connection.OptionRedisInstanceID, "instanceId")

	instanceID, err := requiredStringArg(args, "instanceId", "alicloud.redis.instance")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.redis.instance")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.redis.instance\x00" + instanceID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RedisClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeInstances(&rkvclient.DescribeInstancesRequest{
		RegionId:    new(region),
		InstanceIds: new(instanceID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.Instances != nil {
		for _, inst := range resp.Body.Instances.KVStoreInstance {
			if inst == nil || tea.StringValue(inst.InstanceId) != instanceID {
				continue
			}
			res, err := newRedisInstance(runtime, region, inst)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.redis.instance %q not found in region %q", instanceID, region)
}

func (r *mqlAlicloudRedisInstance) id() (string, error) {
	return r.InstanceId.Data, nil
}

func (r *mqlAlicloudRedisInstance) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudRedisInstance) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.cacheRegion, r.cacheVswitchID)
}

// redisClient returns a region-scoped Redis client together with this
// instance's ID for the per-instance security-posture detail calls.
func (r *mqlAlicloudRedisInstance) redisClient() (*rkvclient.Client, string, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RedisClient(r.region)
	if err != nil {
		return nil, "", err
	}
	return client, r.InstanceId.Data, nil
}

func (r *mqlAlicloudRedisInstance) sslEnabled() (bool, error) {
	client, id, err := r.redisClient()
	if err != nil {
		return false, err
	}
	resp, err := client.DescribeInstanceSSL(&rkvclient.DescribeInstanceSSLRequest{
		InstanceId: new(id),
	})
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Body == nil || resp.Body.SSLEnabled == nil {
		return false, nil
	}
	return tea.StringValue(resp.Body.SSLEnabled) == "Enable", nil
}

func (r *mqlAlicloudRedisInstance) tdeEnabled() (bool, error) {
	client, id, err := r.redisClient()
	if err != nil {
		return false, err
	}
	resp, err := client.DescribeInstanceTDEStatus(&rkvclient.DescribeInstanceTDEStatusRequest{
		InstanceId: new(id),
	})
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Body == nil || resp.Body.TDEStatus == nil {
		return false, nil
	}
	return tea.StringValue(resp.Body.TDEStatus) == "Enabled", nil
}

func (r *mqlAlicloudRedisInstance) securityIPList() ([]any, error) {
	client, id, err := r.redisClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeSecurityIps(&rkvclient.DescribeSecurityIpsRequest{
		InstanceId: new(id),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil || resp.Body.SecurityIpGroups == nil {
		return res, nil
	}

	seen := map[string]struct{}{}
	for _, group := range resp.Body.SecurityIpGroups.SecurityIpGroup {
		if group == nil || group.SecurityIpList == nil {
			continue
		}
		for ip := range strings.SplitSeq(*group.SecurityIpList, ",") {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			res = append(res, ip)
		}
	}
	return res, nil
}

// securityGroups resolves the security groups attached to the instance. The
// group IDs come from DescribeSecurityGroupConfiguration, which is called once
// per instance because the runtime memoizes this field.
func (r *mqlAlicloudRedisInstance) securityGroups() ([]any, error) {
	ids, err := r.fetchSecurityGroupIds()
	if err != nil {
		return nil, err
	}
	return resolveEcsSecuritygroups(r.MqlRuntime, r.region, ids)
}

func (r *mqlAlicloudRedisInstance) fetchSecurityGroupIds() ([]any, error) {
	client, id, err := r.redisClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeSecurityGroupConfiguration(&rkvclient.DescribeSecurityGroupConfigurationRequest{
		InstanceId: new(id),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil || resp.Body.Items == nil {
		return res, nil
	}
	for _, rel := range resp.Body.Items.EcsSecurityGroupRelation {
		if rel == nil || rel.SecurityGroupId == nil {
			continue
		}
		res = append(res, *rel.SecurityGroupId)
	}
	return res, nil
}

func (r *mqlAlicloudRedisInstance) authEnabled() (bool, error) {
	client, id, err := r.redisClient()
	if err != nil {
		return false, err
	}
	resp, err := client.DescribeInstanceAttribute(&rkvclient.DescribeInstanceAttributeRequest{
		InstanceId: new(id),
	})
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Instances == nil {
		return false, nil
	}
	for _, attr := range resp.Body.Instances.DBInstanceAttribute {
		if attr == nil || attr.VpcAuthMode == nil {
			continue
		}
		// VpcAuthMode is "Open" when password authentication is enforced and
		// "Close" when password-free access is enabled.
		return tea.StringValue(attr.VpcAuthMode) == "Open", nil
	}
	return false, nil
}
