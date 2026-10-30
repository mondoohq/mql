// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	tea "github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAlicloudVpc) flowLogs() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.VpcClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(50)
		for {
			resp, err := client.DescribeFlowLogs(&vpcclient.DescribeFlowLogsRequest{
				RegionId:   new(region),
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather
				// than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.FlowLogs == nil {
				break
			}

			items := resp.Body.FlowLogs.FlowLog
			for _, fl := range items {
				if fl == nil || fl.FlowLogId == nil {
					continue
				}
				mqlFlowLog, err := newVpcFlowLog(r.MqlRuntime, region, fl)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlFlowLog)
			}

			total := 0
			if resp.Body.TotalCount != nil {
				total, _ = strconv.Atoi(*resp.Body.TotalCount)
			}
			if len(items) < int(pageSize) || (total > 0 && int(pageNumber)*int(pageSize) >= total) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// flowLogs lists the flow logs whose monitored resource is this VPC, in the
// VPC's region. It backs alicloud.vpc.network.flowLogs so a VPC-scoped asset can
// assert its own flow-log coverage without scanning the whole account. vSwitch-
// and ENI-scoped flow logs are excluded by filtering the request on this VPC id.
func (r *mqlAlicloudVpcNetwork) flowLogs() ([]any, error) {
	if r.cacheVpcID == "" || r.cacheRegion == "" {
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(r.cacheRegion)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(50)
	for {
		resp, err := client.DescribeFlowLogs(&vpcclient.DescribeFlowLogsRequest{
			RegionId:     new(r.cacheRegion),
			ResourceType: new("VPC"),
			ResourceId:   new(r.cacheVpcID),
			PageNumber:   new(pageNumber),
			PageSize:     new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.FlowLogs == nil {
			break
		}

		items := resp.Body.FlowLogs.FlowLog
		for _, fl := range items {
			if fl == nil || fl.FlowLogId == nil {
				continue
			}
			mqlFlowLog, err := newVpcFlowLog(r.MqlRuntime, r.cacheRegion, fl)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFlowLog)
		}

		total := 0
		if resp.Body.TotalCount != nil {
			total, _ = strconv.Atoi(*resp.Body.TotalCount)
		}
		if len(items) < int(pageSize) || (total > 0 && int(pageNumber)*int(pageSize) >= total) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// newVpcFlowLog builds a fully populated alicloud.vpc.flowLog from a
// DescribeFlowLogs item within a region.
func newVpcFlowLog(runtime *plugin.Runtime, region string, fl *vpcclient.DescribeFlowLogsResponseBodyFlowLogsFlowLog) (*mqlAlicloudVpcFlowLog, error) {
	trafficPath := []any{}
	if fl.TrafficPath != nil {
		for _, p := range fl.TrafficPath.TrafficPathList {
			if p != nil {
				trafficPath = append(trafficPath, tea.StringValue(p))
			}
		}
	}

	tags := map[string]any{}
	if fl.Tags != nil {
		for _, t := range fl.Tags.Tag {
			if t == nil || t.Key == nil {
				continue
			}
			tags[*t.Key] = tea.StringValue(t.Value)
		}
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.flowLog", map[string]*llx.RawData{
		"__id":                llx.StringData(region + "/" + tea.StringValue(fl.FlowLogId)),
		"regionId":            llx.StringData(region),
		"flowLogId":           llx.StringDataPtr(fl.FlowLogId),
		"flowLogName":         llx.StringDataPtr(fl.FlowLogName),
		"description":         llx.StringDataPtr(fl.Description),
		"status":              llx.StringDataPtr(fl.Status),
		"businessStatus":      llx.StringDataPtr(fl.BusinessStatus),
		"resourceId":          llx.StringDataPtr(fl.ResourceId),
		"resourceType":        llx.StringDataPtr(fl.ResourceType),
		"trafficType":         llx.StringDataPtr(fl.TrafficType),
		"trafficPath":         llx.ArrayData(trafficPath, types.String),
		"ipVersion":           llx.StringDataPtr(fl.IpVersion),
		"aggregationInterval": llx.IntData(int64(tea.Int32Value(fl.AggregationInterval))),
		"projectName":         llx.StringDataPtr(fl.ProjectName),
		"logStoreName":        llx.StringDataPtr(fl.LogStoreName),
		"resourceGroupId":     llx.StringDataPtr(fl.ResourceGroupId),
		"creationTime":        llx.TimeDataPtr(rdsParseTime(fl.CreationTime)),
		"deliverStatus":       llx.StringDataPtr(fl.FlowLogDeliverStatus),
		"deliverErrorMessage": llx.StringDataPtr(fl.FlowLogDeliverErrorMessage),
		"tags":                llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudVpcFlowLog), nil
}

func (r *mqlAlicloudVpcFlowLog) id() (string, error) {
	return r.RegionId.Data + "/" + r.FlowLogId.Data, nil
}

func (r *mqlAlicloudVpcFlowLog) logstore() (*mqlAlicloudLogLogstore, error) {
	store, err := resolveLogStore(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data, r.LogStoreName.Data)
	if err != nil || store == nil {
		r.Logstore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return store, nil
}

// project resolves the Log Service project the flow log delivers to. The flow
// log outlives its delivery target, so a project that no longer exists (or that
// lives in another account) yields null rather than failing the flow log.
func (r *mqlAlicloudVpcFlowLog) project() (*mqlAlicloudLogProject, error) {
	project, err := resolveLogProject(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data)
	if err != nil || project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

func (r *mqlAlicloudVpcFlowLog) network() (*mqlAlicloudVpcNetwork, error) {
	if !strings.EqualFold(r.ResourceType.Data, "VPC") {
		r.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	network, err := resolveVpcNetwork(r.MqlRuntime, r.RegionId.Data, r.ResourceId.Data)
	if err != nil || network == nil {
		r.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return network, nil
}

func (r *mqlAlicloudVpcFlowLog) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if !strings.EqualFold(r.ResourceType.Data, "VSwitch") {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	vswitch, err := resolveVpcVswitch(r.MqlRuntime, r.RegionId.Data, r.ResourceId.Data)
	if err != nil || vswitch == nil {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return vswitch, nil
}
