// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	rdsclient "github.com/alibabacloud-go/rds-20140815/v17/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// rdsParseTime parses an RFC3339 timestamp returned by the RDS API, returning
// nil when the input is nil or cannot be parsed.
func rdsParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// rdsStatusEnabled reports whether an RDS on/off status string means on. The
// RDS APIs are not consistent about the spelling: TDE reports Enabled, SQL
// Explorer reports Enable, and both have been seen with surrounding space.
// Anything else, including a nil or empty value, counts as off so a "must be
// enabled" check fails rather than passing on a value nobody recognised.
func rdsStatusEnabled(status *string) bool {
	if status == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(*status)) {
	case "enable", "enabled":
		return true
	default:
		return false
	}
}

// rdsRetentionDays converts the SQL Explorer retention window, which the API
// returns as a string, to a day count. An absent or unparseable value is 0,
// which fails a minimum-retention check rather than satisfying it.
func rdsRetentionDays(configValue *string) int64 {
	if configValue == nil {
		return 0
	}
	days, err := strconv.Atoi(strings.TrimSpace(*configValue))
	if err != nil || days < 0 {
		return 0
	}
	return int64(days)
}

// rdsRunningParameters flattens the running parameter list into a name-keyed
// map. It reads RunningParameters, the values in effect on the instance, and
// not ConfigParameters, which also carries changes that have not been applied
// yet and would report a setting as active before the instance restarts.
func rdsRunningParameters(body *rdsclient.DescribeParametersResponseBody) map[string]any {
	res := map[string]any{}
	if body == nil || body.RunningParameters == nil {
		return res
	}
	for _, param := range body.RunningParameters.DBInstanceParameter {
		if param == nil || param.ParameterName == nil || *param.ParameterName == "" {
			continue
		}
		res[*param.ParameterName] = tea.StringValue(param.ParameterValue)
	}
	return res
}

func (r *mqlAlicloudRds) id() (string, error) {
	return "alicloud.rds", nil
}

type mqlAlicloudRdsInstanceInternal struct {
	region     string
	instanceId string

	cacheRegion           string
	cacheVpcID            string
	cacheVswitchID        string
	cacheMasterInstanceID string

	attrLock sync.Mutex
	attrDone bool
	attr     *rdsclient.DescribeDBInstanceAttributeResponseBodyItemsDBInstanceAttribute

	sslLock sync.Mutex
	sslDone bool
	ssl     *rdsclient.DescribeDBInstanceSSLResponseBody

	tdeLock sync.Mutex
	tdeDone bool
	tde     *rdsclient.DescribeDBInstanceTDEResponseBody
}

func (r *mqlAlicloudRds) instances() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.RdsClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		for {
			resp, err := client.DescribeDBInstances(&rdsclient.DescribeDBInstancesRequest{
				RegionId:   new(region),
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil {
				// A region may not have RDS enabled or the credential may lack
				// access there. Skip it rather than failing the whole list.
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.Items == nil {
				break
			}

			items := resp.Body.Items.DBInstance
			for _, inst := range items {
				if inst == nil || inst.DBInstanceId == nil {
					continue
				}

				mqlInst, err := newRdsInstance(r.MqlRuntime, region, inst)
				if err != nil {
					return nil, err
				}
				// instance tags cost a DescribeTags call each, so only read them
				// when a tag filter is actually set
				if conn.Filters.General.HasTags() {
					tags := mqlInst.GetTags()
					if tags.Error != nil {
						return nil, tags.Error
					}
					if filteredOutByTags(conn, tags.Data) {
						continue
					}
				}
				res = append(res, mqlInst)
			}

			if len(items) == 0 || int(pageNumber)*int(pageSize) >= int(tea.Int32Value(resp.Body.TotalRecordCount)) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// newRdsInstance builds a fully populated alicloud.rds.instance from a
// DescribeDBInstances list item within a region. It is shared by the instances
// list accessor and the by-id init so both produce identical resources (no husk).
func newRdsInstance(runtime *plugin.Runtime, region string, inst *rdsclient.DescribeDBInstancesResponseBodyItemsDBInstance) (*mqlAlicloudRdsInstance, error) {
	id := tea.StringValue(inst.DBInstanceId) + "/" + region
	resource, err := CreateResource(runtime, "alicloud.rds.instance", map[string]*llx.RawData{
		"__id":                  llx.StringData(id),
		"dbInstanceId":          llx.StringDataPtr(inst.DBInstanceId),
		"dbInstanceDescription": llx.StringDataPtr(inst.DBInstanceDescription),
		"engine":                llx.StringDataPtr(inst.Engine),
		"engineVersion":         llx.StringDataPtr(inst.EngineVersion),
		"dbInstanceStatus":      llx.StringDataPtr(inst.DBInstanceStatus),
		"dbInstanceType":        llx.StringDataPtr(inst.DBInstanceType),
		"dbInstanceClass":       llx.StringDataPtr(inst.DBInstanceClass),
		"dbInstanceStorageType": llx.StringDataPtr(inst.DBInstanceStorageType),
		"dbInstanceNetType":     llx.StringDataPtr(inst.DBInstanceNetType),
		"connectionMode":        llx.StringDataPtr(inst.ConnectionMode),
		"connectionString":      llx.StringDataPtr(inst.ConnectionString),
		"regionId":              llx.StringDataPtr(inst.RegionId),
		"zoneId":                llx.StringDataPtr(inst.ZoneId),
		"instanceNetworkType":   llx.StringDataPtr(inst.InstanceNetworkType),
		"payType":               llx.StringDataPtr(inst.PayType),
		"createTime":            llx.TimeDataPtr(rdsParseTime(inst.CreateTime)),
		"expireTime":            llx.TimeDataPtr(rdsParseTime(inst.ExpireTime)),
		"lockMode":              llx.StringDataPtr(inst.LockMode),
		"lockReason":            llx.StringDataPtr(inst.LockReason),
		"category":              llx.StringDataPtr(inst.Category),
		"deletionProtection":    llx.BoolDataPtr(inst.DeletionProtection),
		"resourceGroupId":       llx.StringDataPtr(inst.ResourceGroupId),
	})
	if err != nil {
		return nil, err
	}

	mqlInst := resource.(*mqlAlicloudRdsInstance)
	mqlInst.region = region
	mqlInst.instanceId = tea.StringValue(inst.DBInstanceId)
	mqlInst.cacheRegion = region
	mqlInst.cacheVpcID = tea.StringValue(inst.VpcId)
	mqlInst.cacheVswitchID = tea.StringValue(inst.VSwitchId)
	mqlInst.cacheMasterInstanceID = tea.StringValue(inst.MasterInstanceId)
	return mqlInst, nil
}

// resolveRdsInstance returns the typed RDS instance for a native DB instance id
// within a region, or (nil, nil) when dbInstanceID is empty (the caller sets
// StateIsNull). The underlying init reuses an already-listed instance from the
// resource cache and otherwise fetches it via DescribeDBInstances.
func resolveRdsInstance(runtime *plugin.Runtime, region, dbInstanceID string) (*mqlAlicloudRdsInstance, error) {
	if dbInstanceID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.rds.instance", map[string]*llx.RawData{
		"dbInstanceId": llx.StringData(dbInstanceID),
		"regionId":     llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudRdsInstance), nil
}

// initAlicloudRdsInstance resolves an RDS instance by its native DB instance id
// within a region. It backs both direct lookups and the typed masterInstance()
// self-reference, reusing the cached instance when it has already been listed.
func initAlicloudRdsInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered RDS instance asset, resolve the instance the asset is
	// scoped to
	args = scopedInitArgs(runtime, args, connection.OptionRdsInstanceID, "dbInstanceId")

	dbInstanceID, err := requiredStringArg(args, "dbInstanceId", "alicloud.rds.instance")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.rds.instance")
	if err != nil {
		return nil, nil, err
	}

	// Matches the instance __id: dbInstanceId + "/" + region.
	key := dbInstanceID + "/" + region
	if x, ok := runtime.Resources.Get("alicloud.rds.instance\x00" + key); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeDBInstances(&rdsclient.DescribeDBInstancesRequest{
		RegionId:     new(region),
		DBInstanceId: new(dbInstanceID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.Items != nil {
		for _, inst := range resp.Body.Items.DBInstance {
			if inst == nil || inst.DBInstanceId == nil || *inst.DBInstanceId != dbInstanceID {
				continue
			}
			res, err := newRdsInstance(runtime, region, inst)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.rds.instance %q not found in region %q", dbInstanceID, region)
}

func (r *mqlAlicloudRdsInstance) id() (string, error) {
	return r.instanceId + "/" + r.region, nil
}

// fetchAttribute lazily loads the per-instance DescribeDBInstanceAttribute
// detail and caches it. Returns nil when the call fails or returns no detail,
// so callers fall back to their safe default.
func (r *mqlAlicloudRdsInstance) fetchAttribute() *rdsclient.DescribeDBInstanceAttributeResponseBodyItemsDBInstanceAttribute {
	r.attrLock.Lock()
	defer r.attrLock.Unlock()
	if r.attrDone {
		return r.attr
	}
	r.attrDone = true

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return nil
	}
	resp, err := client.DescribeDBInstanceAttribute(&rdsclient.DescribeDBInstanceAttributeRequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil || resp.Body.Items == nil {
		return nil
	}
	attrs := resp.Body.Items.DBInstanceAttribute
	if len(attrs) == 0 {
		return nil
	}
	r.attr = attrs[0]
	return r.attr
}

// The blue-green fields, compute burst, vector support and read-only state all
// arrive on the same DescribeDBInstanceAttribute detail, so they share the one
// cached fetch rather than making a call each.

func (r *mqlAlicloudRdsInstance) blueGreenDeploymentName() (string, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return "", nil
	}
	return tea.StringValue(attr.BlueGreenDeploymentName), nil
}

func (r *mqlAlicloudRdsInstance) blueInstanceName() (string, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return "", nil
	}
	return tea.StringValue(attr.BlueInstanceName), nil
}

func (r *mqlAlicloudRdsInstance) greenInstanceName() (string, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return "", nil
	}
	return tea.StringValue(attr.GreenInstanceName), nil
}

func (r *mqlAlicloudRdsInstance) computeBurstEnabled() (bool, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return false, nil
	}
	return tea.BoolValue(attr.ComputeBurstEnabled), nil
}

func (r *mqlAlicloudRdsInstance) vectorSupportStatus() (string, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return "", nil
	}
	return tea.StringValue(attr.VectorSupportStatus), nil
}

func (r *mqlAlicloudRdsInstance) readOnlyStatus() (string, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return "", nil
	}
	return tea.StringValue(attr.ReadOnlyStatus), nil
}

func (r *mqlAlicloudRdsInstance) dbInstanceStorage() (int64, error) {
	attr := r.fetchAttribute()
	if attr == nil {
		return 0, nil
	}
	return int64(tea.Int32Value(attr.DBInstanceStorage)), nil
}

func (r *mqlAlicloudRdsInstance) port() (int64, error) {
	attr := r.fetchAttribute()
	if attr == nil || attr.Port == nil {
		return 0, nil
	}
	p, err := strconv.Atoi(strings.TrimSpace(*attr.Port))
	if err != nil {
		return 0, nil
	}
	return int64(p), nil
}

func (r *mqlAlicloudRdsInstance) tags() (map[string]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return map[string]any{}, nil
	}
	resp, err := client.DescribeTags(&rdsclient.DescribeTagsRequest{
		RegionId:     new(r.region),
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil || resp.Body.Items == nil {
		return map[string]any{}, nil
	}
	res := map[string]any{}
	for _, t := range resp.Body.Items.TagInfos {
		if t == nil || t.TagKey == nil {
			continue
		}
		res[*t.TagKey] = tea.StringValue(t.TagValue)
	}
	return res, nil
}

// fetchSSL lazily loads the per-instance DescribeDBInstanceSSL detail and
// caches it. Returns nil when the call fails, so callers fall back to their
// safe default.
func (r *mqlAlicloudRdsInstance) fetchSSL() *rdsclient.DescribeDBInstanceSSLResponseBody {
	r.sslLock.Lock()
	defer r.sslLock.Unlock()
	if r.sslDone {
		return r.ssl
	}
	r.sslDone = true

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return nil
	}
	resp, err := client.DescribeDBInstanceSSL(&rdsclient.DescribeDBInstanceSSLRequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil {
		return nil
	}
	r.ssl = resp.Body
	return r.ssl
}

func (r *mqlAlicloudRdsInstance) sslEnabled() (bool, error) {
	ssl := r.fetchSSL()
	if ssl == nil || ssl.SSLEnabled == nil {
		return false, nil
	}
	// MySQL/SQL Server report Yes/No, PostgreSQL reports on/off.
	switch strings.ToLower(strings.TrimSpace(*ssl.SSLEnabled)) {
	case "yes", "on", "1":
		return true, nil
	default:
		return false, nil
	}
}

func (r *mqlAlicloudRdsInstance) sslExpireTime() (*time.Time, error) {
	ssl := r.fetchSSL()
	if ssl == nil {
		return nil, nil
	}
	return rdsParseTime(ssl.SSLExpireTime), nil
}

// fetchTDE lazily loads the per-instance DescribeDBInstanceTDE detail and
// caches it, so the TDE status, the key generation mode and the customer key
// share a single call. Returns nil when the call fails or returns no detail, so
// callers fall back to their safe default: encryption reads as off rather than
// on, which fails an encryption check instead of passing it vacuously.
func (r *mqlAlicloudRdsInstance) fetchTDE() *rdsclient.DescribeDBInstanceTDEResponseBody {
	r.tdeLock.Lock()
	defer r.tdeLock.Unlock()
	if r.tdeDone {
		return r.tde
	}
	r.tdeDone = true

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return nil
	}
	resp, err := client.DescribeDBInstanceTDE(&rdsclient.DescribeDBInstanceTDERequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil {
		return nil
	}
	r.tde = resp.Body
	return r.tde
}

func (r *mqlAlicloudRdsInstance) tdeEnabled() (bool, error) {
	tde := r.fetchTDE()
	if tde == nil {
		return false, nil
	}
	return rdsStatusEnabled(tde.TDEStatus), nil
}

func (r *mqlAlicloudRdsInstance) tdeMode() (string, error) {
	tde := r.fetchTDE()
	if tde == nil {
		return "", nil
	}
	return tea.StringValue(tde.TDEMode), nil
}

// tdeEncryptionKey resolves the customer key protecting the instance. It is
// null whenever the instance is not encrypted with a key of its own: TDE off,
// or on with a key Alibaba Cloud generated and holds, in which case the API
// reports no EncryptionKey at all.
func (r *mqlAlicloudRdsInstance) tdeEncryptionKey() (*mqlAlicloudKmsKey, error) {
	tde := r.fetchTDE()
	if tde == nil || tea.StringValue(tde.EncryptionKey) == "" {
		r.TdeEncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(r.MqlRuntime, r.cacheRegion, tea.StringValue(tde.EncryptionKey))
	if err != nil || key == nil {
		r.TdeEncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}

// sqlAuditEnabled reports whether SQL Explorer is collecting statements. A
// failed read returns false so an "auditing is on" check fails rather than
// passing on an instance nobody could read.
func (r *mqlAlicloudRdsInstance) sqlAuditEnabled() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return false, nil
	}
	resp, err := client.DescribeSQLCollectorPolicy(&rdsclient.DescribeSQLCollectorPolicyRequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil {
		return false, nil
	}
	return rdsStatusEnabled(resp.Body.SQLCollectorStatus), nil
}

// sqlAuditRetentionDays reads the retention window from
// DescribeSQLCollectorRetention rather than the DescribeSQLCollectorPolicy
// StoragePeriod field, which the API documents as reserved and leaves at 0.
func (r *mqlAlicloudRdsInstance) sqlAuditRetentionDays() (int64, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return 0, nil
	}
	resp, err := client.DescribeSQLCollectorRetention(&rdsclient.DescribeSQLCollectorRetentionRequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil {
		return 0, nil
	}
	return rdsRetentionDays(resp.Body.ConfigValue), nil
}

// parameters returns the parameter values in effect on the running instance,
// keyed by parameter name. A fetch error is propagated rather than reported as
// an empty map: an empty map reads as "the parameter is unset", which is a
// legitimate answer, and would let a check on log_connections pass judgement on
// an instance whose parameters were never read.
func (r *mqlAlicloudRdsInstance) parameters() (map[string]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeParameters(&rdsclient.DescribeParametersRequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return map[string]any{}, nil
	}
	return rdsRunningParameters(resp.Body), nil
}

func (r *mqlAlicloudRdsInstance) securityIPList() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeDBInstanceIPArrayList(&rdsclient.DescribeDBInstanceIPArrayListRequest{
		DBInstanceId: new(r.instanceId),
	})
	// Propagate a real fetch error rather than returning an empty list: a
	// swallowed error here reads as a locked-down (empty) whitelist and lets an
	// actually-open instance pass an exposure check. A genuinely empty response
	// (no error, no items) is still a legitimate empty whitelist.
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Items == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, arr := range resp.Body.Items.DBInstanceIPArray {
		if arr == nil || arr.SecurityIPList == nil {
			continue
		}
		for ip := range strings.SplitSeq(*arr.SecurityIPList, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				res = append(res, ip)
			}
		}
	}
	return res, nil
}

func (r *mqlAlicloudRdsInstance) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudRdsInstance) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.cacheRegion, r.cacheVswitchID)
}

// rdsPeerInstance reads the instance id and region of a disaster recovery
// replica or warm standby from the DescribeDBInstanceAttribute detail. The peer
// may live in another region; when the detail names none, it is assumed to
// share the instance's own region. An empty id means no peer is configured.
func rdsPeerInstance(insName, peerRegion *string, ownRegion string) (string, string) {
	id := strings.TrimSpace(tea.StringValue(insName))
	if id == "" {
		return "", ""
	}
	region := strings.TrimSpace(tea.StringValue(peerRegion))
	if region == "" {
		region = ownRegion
	}
	return id, region
}

func (r *mqlAlicloudRdsInstance) drReplicaInstance() (*mqlAlicloudRdsInstance, error) {
	var id, region string
	if attr := r.fetchAttribute(); attr != nil && attr.DrReplicaInfo != nil {
		id, region = rdsPeerInstance(attr.DrReplicaInfo.InsName, attr.DrReplicaInfo.Region, r.region)
	}
	if id == "" {
		r.DrReplicaInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRdsInstance(r.MqlRuntime, region, id)
}

func (r *mqlAlicloudRdsInstance) warmStandbyInstance() (*mqlAlicloudRdsInstance, error) {
	var id, region string
	if attr := r.fetchAttribute(); attr != nil && attr.WarmStandbyInfo != nil {
		id, region = rdsPeerInstance(attr.WarmStandbyInfo.InsName, attr.WarmStandbyInfo.Region, r.region)
	}
	if id == "" {
		r.WarmStandbyInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRdsInstance(r.MqlRuntime, region, id)
}

func (r *mqlAlicloudRdsInstance) masterInstance() (*mqlAlicloudRdsInstance, error) {
	if r.cacheMasterInstanceID == "" {
		r.MasterInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRdsInstance(r.MqlRuntime, r.cacheRegion, r.cacheMasterInstanceID)
}

// securityGroups resolves the security groups attached to the instance. The
// group IDs come from DescribeSecurityGroupConfiguration, which is called once
// per instance because the runtime memoizes this field.
func (r *mqlAlicloudRdsInstance) securityGroups() ([]any, error) {
	ids, err := r.fetchSecurityGroupIds()
	if err != nil {
		return nil, err
	}
	return resolveEcsSecuritygroups(r.MqlRuntime, r.region, ids)
}

func (r *mqlAlicloudRdsInstance) fetchSecurityGroupIds() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RdsClient(r.region)
	if err != nil {
		return []any{}, nil
	}
	resp, err := client.DescribeSecurityGroupConfiguration(&rdsclient.DescribeSecurityGroupConfigurationRequest{
		DBInstanceId: new(r.instanceId),
	})
	if err != nil || resp == nil || resp.Body == nil || resp.Body.Items == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, rel := range resp.Body.Items.EcsSecurityGroupRelation {
		if rel == nil || rel.SecurityGroupId == nil {
			continue
		}
		res = append(res, *rel.SecurityGroupId)
	}
	return res, nil
}
