// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// mqlAlicloudPolardbClusterInternal caches the values a cluster needs to make
// its per-cluster security-posture detail calls and to resolve its typed VPC
// and vSwitch references.
type mqlAlicloudPolardbClusterInternal struct {
	polardbAuditState
	region         string
	dbClusterId    string
	cacheVpcID     string
	cacheVswitchID string
}

func polardbStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// polardbParseTime parses an Alibaba Cloud RFC3339 timestamp, returning nil on a
// nil, empty, or unparseable value.
func polardbParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

func polardbTagsToMap(tags *polardb.DescribeDBClustersResponseBodyItemsDBClusterTags) map[string]any {
	res := map[string]any{}
	if tags == nil {
		return res
	}
	for _, t := range tags.Tag {
		if t == nil || t.Key == nil {
			continue
		}
		res[*t.Key] = polardbStr(t.Value)
	}
	return res
}

func polardbNodesToDict(nodes *polardb.DescribeDBClustersResponseBodyItemsDBClusterDBNodes) []any {
	res := []any{}
	if nodes == nil {
		return res
	}
	for _, n := range nodes.DBNode {
		if n == nil {
			continue
		}
		res = append(res, map[string]any{
			"dbNodeId":       polardbStr(n.DBNodeId),
			"dbNodeClass":    polardbStr(n.DBNodeClass),
			"dbNodeRole":     polardbStr(n.DBNodeRole),
			"zoneId":         polardbStr(n.ZoneId),
			"regionId":       polardbStr(n.RegionId),
			"imciSwitch":     polardbStr(n.ImciSwitch),
			"hotReplicaMode": polardbStr(n.HotReplicaMode),
			"serverless":     polardbStr(n.Serverless),
		})
	}
	return res
}

func (r *mqlAlicloudPolardb) id() (string, error) {
	return "alicloud.polardb", nil
}

func (r *mqlAlicloudPolardb) clusters() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.PolarDBClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		for {
			regionId := region
			pn := pageNumber
			ps := pageSize
			resp, err := client.DescribeDBClusters(&polardb.DescribeDBClustersRequest{
				RegionId:   &regionId,
				PageNumber: &pn,
				PageSize:   &ps,
			})
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.Items == nil {
				break
			}

			clusters := resp.Body.Items.DBCluster
			for _, c := range clusters {
				if c == nil || c.DBClusterId == nil {
					continue
				}

				cluster, err := newPolardbCluster(r.MqlRuntime, region, c)
				if err != nil {
					return nil, err
				}
				// DescribeDBClusters returns tags inline, so the filter costs
				// nothing beyond the listing already made
				if filteredOutByTags(conn, cluster.Tags.Data) {
					continue
				}
				res = append(res, cluster)
			}

			// Stop once the final page returns fewer than a full page of clusters.
			if len(clusters) < int(pageSize) {
				break
			}
			pageNumber++
		}
	}

	return res, nil
}

// newPolardbCluster builds a fully populated alicloud.polardb.cluster from a
// DescribeDBClusters list item within a region. It is shared by the clusters
// list accessor and the by-id init so both produce identical resources.
func newPolardbCluster(runtime *plugin.Runtime, region string, c *polardb.DescribeDBClustersResponseBodyItemsDBCluster) (*mqlAlicloudPolardbCluster, error) {
	id := region + "/" + tea.StringValue(c.DBClusterId)
	resource, err := CreateResource(runtime, "alicloud.polardb.cluster", map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"dbClusterId":          llx.StringDataPtr(c.DBClusterId),
		"dbClusterDescription": llx.StringDataPtr(c.DBClusterDescription),
		"dbClusterStatus":      llx.StringDataPtr(c.DBClusterStatus),
		"dbType":               llx.StringDataPtr(c.DBType),
		"dbVersion":            llx.StringDataPtr(c.DBVersion),
		"engine":               llx.StringDataPtr(c.Engine),
		"category":             llx.StringDataPtr(c.Category),
		"subCategory":          llx.StringDataPtr(c.SubCategory),
		"dbNodeClass":          llx.StringDataPtr(c.DBNodeClass),
		"dbNodeNumber":         llx.IntDataPtr(c.DBNodeNumber),
		"cpuCores":             llx.StringDataPtr(c.CpuCores),
		"memorySize":           llx.StringDataPtr(c.MemorySize),
		"storageUsed":          llx.IntDataPtr(c.StorageUsed),
		"storageType":          llx.StringDataPtr(c.StorageType),
		"storagePayType":       llx.StringDataPtr(c.StoragePayType),
		"storageSpace":         llx.IntDataPtr(c.StorageSpace),
		"regionId":             llx.StringDataPtr(c.RegionId),
		"zoneId":               llx.StringDataPtr(c.ZoneId),
		"payType":              llx.StringDataPtr(c.PayType),
		"createTime":           llx.TimeDataPtr(polardbParseTime(c.CreateTime)),
		"expireTime":           llx.TimeDataPtr(polardbParseTime(c.ExpireTime)),
		"expired":              llx.StringDataPtr(c.Expired),
		"lockMode":             llx.StringDataPtr(c.LockMode),
		"deletionLock":         llx.IntDataPtr(c.DeletionLock),
		"resourceGroupId":      llx.StringDataPtr(c.ResourceGroupId),
		"serverlessType":       llx.StringDataPtr(c.ServerlessType),
		"dbClusterNetworkType": llx.StringDataPtr(c.DBClusterNetworkType),
		"aiType":               llx.StringDataPtr(c.AiType),
		"hotStandbyCluster":    llx.StringDataPtr(c.HotStandbyCluster),
		"strictConsistency":    llx.StringDataPtr(c.StrictConsistency),
		"tags":                 llx.MapData(polardbTagsToMap(c.Tags), types.String),
		"dbNodes":              llx.ArrayData(polardbNodesToDict(c.DBNodes), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	cluster := resource.(*mqlAlicloudPolardbCluster)
	cluster.region = region
	cluster.dbClusterId = tea.StringValue(c.DBClusterId)
	cluster.cacheVpcID = polardbStr(c.VpcId)
	cluster.cacheVswitchID = polardbStr(c.VswitchId)
	return cluster, nil
}

// initAlicloudPolardbCluster resolves a PolarDB cluster by its native cluster id
// within a region, reusing an already-listed cluster from the resource cache. It
// also backs the discovered polardb-cluster asset, which scopes the connection
// to one cluster.
func initAlicloudPolardbCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered PolarDB cluster asset, resolve the cluster the asset is
	// scoped to
	args = scopedInitArgs(runtime, args, connection.OptionPolardbClusterID, "dbClusterId")

	clusterID, err := requiredStringArg(args, "dbClusterId", "alicloud.polardb.cluster")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.polardb.cluster")
	if err != nil {
		return nil, nil, err
	}

	// Matches the cluster __id: region + "/" + dbClusterId.
	if x, ok := runtime.Resources.Get("alicloud.polardb.cluster\x00" + region + "/" + clusterID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeDBClusters(&polardb.DescribeDBClustersRequest{
		RegionId:     new(region),
		DBClusterIds: new(clusterID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.Items != nil {
		for _, c := range resp.Body.Items.DBCluster {
			if c == nil || tea.StringValue(c.DBClusterId) != clusterID {
				continue
			}
			res, err := newPolardbCluster(runtime, region, c)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.polardb.cluster %q not found in region %q", clusterID, region)
}

func (r *mqlAlicloudPolardbCluster) id() (string, error) {
	return r.region + "/" + r.dbClusterId, nil
}

func (r *mqlAlicloudPolardbCluster) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcID)
}

func (r *mqlAlicloudPolardbCluster) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.region, r.cacheVswitchID)
}

// storageMax resolves the cluster's maximum storage capacity from the cluster
// attribute detail, which is not returned by the cluster list.
func (r *mqlAlicloudPolardbCluster) storageMax() (int64, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return 0, err
	}

	dbClusterId := r.dbClusterId
	resp, err := client.DescribeDBClusterAttribute(&polardb.DescribeDBClusterAttributeRequest{
		DBClusterId: &dbClusterId,
	})
	if err != nil {
		return 0, err
	}
	if resp == nil || resp.Body == nil || resp.Body.StorageMax == nil {
		return 0, nil
	}
	return *resp.Body.StorageMax, nil
}

func (r *mqlAlicloudPolardbCluster) sslEnabled() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return false, err
	}

	dbClusterId := r.dbClusterId
	resp, err := client.DescribeDBClusterSSL(&polardb.DescribeDBClusterSSLRequest{
		DBClusterId: &dbClusterId,
	})
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Body == nil {
		return false, nil
	}
	for _, item := range resp.Body.Items {
		if item != nil && item.SSLEnabled != nil && strings.EqualFold(*item.SSLEnabled, "Enabled") {
			return true, nil
		}
	}
	return false, nil
}

func (r *mqlAlicloudPolardbCluster) tdeEnabled() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return false, err
	}

	dbClusterId := r.dbClusterId
	resp, err := client.DescribeDBClusterTDE(&polardb.DescribeDBClusterTDERequest{
		DBClusterId: &dbClusterId,
	})
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Body == nil || resp.Body.TDEStatus == nil {
		return false, nil
	}
	return strings.EqualFold(*resp.Body.TDEStatus, "Enabled"), nil
}

func (r *mqlAlicloudPolardbCluster) accessWhitelist() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return nil, err
	}

	dbClusterId := r.dbClusterId
	resp, err := client.DescribeDBClusterAccessWhitelist(&polardb.DescribeDBClusterAccessWhitelistRequest{
		DBClusterId: &dbClusterId,
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil || resp.Body.Items == nil {
		return res, nil
	}
	for _, arr := range resp.Body.Items.DBClusterIPArray {
		if arr == nil || arr.SecurityIps == nil {
			continue
		}
		for ip := range strings.SplitSeq(*arr.SecurityIps, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				res = append(res, ip)
			}
		}
	}
	return res, nil
}

func (r *mqlAlicloudPolardbCluster) endpoints() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return nil, err
	}

	dbClusterId := r.dbClusterId
	resp, err := client.DescribeDBClusterEndpoints(&polardb.DescribeDBClusterEndpointsRequest{
		DBClusterId: &dbClusterId,
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil {
		return res, nil
	}
	for _, item := range resp.Body.Items {
		if item == nil {
			continue
		}
		if len(item.AddressItems) == 0 {
			res = append(res, map[string]any{
				"endpointType":     polardbStr(item.EndpointType),
				"dbEndpointId":     polardbStr(item.DBEndpointId),
				"addressType":      polardbStr(item.NetType),
				"connectionString": polardbStr(item.ConnectionString),
				"port":             polardbStr(item.Port),
				"readWriteMode":    polardbStr(item.ReadWriteMode),
				"nodes":            polardbStr(item.Nodes),
			})
			continue
		}
		for _, addr := range item.AddressItems {
			if addr == nil {
				continue
			}
			res = append(res, map[string]any{
				"endpointType":     polardbStr(item.EndpointType),
				"dbEndpointId":     polardbStr(item.DBEndpointId),
				"addressType":      polardbStr(addr.NetType),
				"connectionString": polardbStr(addr.ConnectionString),
				"port":             polardbStr(addr.Port),
				"readWriteMode":    polardbStr(item.ReadWriteMode),
				"nodes":            polardbStr(item.Nodes),
			})
		}
	}
	return res, nil
}
