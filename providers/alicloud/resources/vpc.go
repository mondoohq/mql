// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// vpcParseTime parses an RFC3339 timestamp string returned by the Alibaba Cloud
// APIs. It returns nil on a nil pointer or an unparseable value so the field
// resolves to null rather than a zero time.
func vpcParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// vpcStrSlice converts a slice of *string into a []any of non-nil string
// values, safe to pass to llx.ArrayData with types.String.
func vpcStrSlice(in []*string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		if s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// vpcTagMap builds a string map from the common Alibaba Cloud Key/Value tag
// pair shape.
func vpcTagMap(pairs []*vpcTag) map[string]any {
	out := map[string]any{}
	for _, p := range pairs {
		if p == nil || p.key == nil {
			continue
		}
		v := ""
		if p.value != nil {
			v = *p.value
		}
		out[*p.key] = v
	}
	return out
}

// vpcTag is a normalized tag pair used by vpcTagMap so the various SDK
// tag shapes can be flattened through one helper.
type vpcTag struct {
	key   *string
	value *string
}

// vpcStr dereferences a *string, returning "" when nil. Used for dict
// values, which carry plain Go scalars rather than RawData.
func vpcStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// vpcInt32 dereferences a *int32, returning 0 when nil.
func vpcInt32(v *int32) int64 {
	if v == nil {
		return 0
	}
	return int64(*v)
}

// vpcBool dereferences a *bool, returning false when nil.
func vpcBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

// vpcAclTotalCount parses the DescribeNetworkAcls TotalCount, which the SDK
// models as a string. It returns -1 when the value is nil or unparseable so the
// caller stops paginating.
func vpcAclTotalCount(s *string) int64 {
	if s == nil || *s == "" {
		return -1
	}
	n, err := strconv.ParseInt(*s, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func (r *mqlAlicloudVpc) id() (string, error) {
	return "alicloud.vpc", nil
}

func (r *mqlAlicloudVpc) networks() ([]any, error) {
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
			req := &vpcclient.DescribeVpcsRequest{
				RegionId:   &region,
				PageNumber: &pageNumber,
				PageSize:   &pageSize,
			}
			resp, err := client.DescribeVpcs(req)
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.Vpcs == nil {
				break
			}

			for _, vpc := range resp.Body.Vpcs.Vpc {
				if vpc == nil || vpc.VpcId == nil {
					continue
				}
				network, err := newVpcNetwork(r.MqlRuntime, region, vpc)
				if err != nil {
					return nil, err
				}
				if mqlNetwork, ok := network.(*mqlAlicloudVpcNetwork); ok &&
					filteredOutByTags(conn, mqlNetwork.Tags.Data) {
					continue
				}
				res = append(res, network)
			}

			if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// mqlAlicloudVpcNetworkInternal caches the region the network was discovered in
// (so its region-scoped __id can be reconstructed) and its own native vpc id
// (so the vswitches, natGateways, and routeTables collections can be listed
// filtered to this VPC).
type mqlAlicloudVpcNetworkInternal struct {
	cacheRegion string
	cacheVpcID  string
}

// newVpcNetwork maps a DescribeVpcs item into an alicloud.vpc.network resource.
// It is shared by the list accessor and initAlicloudVpcNetwork so both produce a
// fully populated resource.
func newVpcNetwork(runtime *plugin.Runtime, region string, vpc *vpcclient.DescribeVpcsResponseBodyVpcsVpc) (plugin.Resource, error) {
	secondary := []any{}
	if vpc.SecondaryCidrBlocks != nil {
		secondary = vpcStrSlice(vpc.SecondaryCidrBlocks.SecondaryCidrBlock)
	}
	userCidrs := []any{}
	if vpc.UserCidrs != nil {
		userCidrs = vpcStrSlice(vpc.UserCidrs.UserCidr)
	}

	ipv6Blocks := []any{}
	if vpc.Ipv6CidrBlocks != nil {
		for _, b := range vpc.Ipv6CidrBlocks.Ipv6CidrBlock {
			if b == nil {
				continue
			}
			ipv6Blocks = append(ipv6Blocks, map[string]any{
				"ipv6CidrBlock": vpcStr(b.Ipv6CidrBlock),
				"ipv6Isp":       vpcStr(b.Ipv6Isp),
			})
		}
	}

	tags := map[string]any{}
	if vpc.Tags != nil {
		pairs := make([]*vpcTag, 0, len(vpc.Tags.Tag))
		for _, t := range vpc.Tags.Tag {
			if t != nil {
				pairs = append(pairs, &vpcTag{key: t.Key, value: t.Value})
			}
		}
		tags = vpcTagMap(pairs)
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.network", map[string]*llx.RawData{
		"__id":                 llx.StringData(region + "/" + vpcStr(vpc.VpcId)),
		"vpcId":                llx.StringDataPtr(vpc.VpcId),
		"vpcName":              llx.StringDataPtr(vpc.VpcName),
		"description":          llx.StringDataPtr(vpc.Description),
		"cidrBlock":            llx.StringDataPtr(vpc.CidrBlock),
		"cidrBlocks":           llx.ArrayData(secondary, types.String),
		"ipv6CidrBlock":        llx.StringDataPtr(vpc.Ipv6CidrBlock),
		"ipv6CidrBlocks":       llx.ArrayData(ipv6Blocks, types.Dict),
		"enabledIpv6":          llx.BoolDataPtr(vpc.EnabledIpv6),
		"status":               llx.StringDataPtr(vpc.Status),
		"isDefault":            llx.BoolDataPtr(vpc.IsDefault),
		"regionId":             llx.StringDataPtr(vpc.RegionId),
		"vRouterId":            llx.StringDataPtr(vpc.VRouterId),
		"creationTime":         llx.TimeDataPtr(vpcParseTime(vpc.CreationTime)),
		"resourceGroupId":      llx.StringDataPtr(vpc.ResourceGroupId),
		"userCidrs":            llx.ArrayData(userCidrs, types.String),
		"dnsHostnameStatus":    llx.StringDataPtr(vpc.DnsHostnameStatus),
		"dhcpOptionsSetId":     llx.StringDataPtr(vpc.DhcpOptionsSetId),
		"dhcpOptionsSetStatus": llx.StringDataPtr(vpc.DhcpOptionsSetStatus),
		"cenStatus":            llx.StringDataPtr(vpc.CenStatus),
		"ownerId":              llx.IntDataPtr(vpc.OwnerId),
		"tags":                 llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	network := resource.(*mqlAlicloudVpcNetwork)
	network.cacheRegion = region
	network.cacheVpcID = vpcStr(vpc.VpcId)
	return network, nil
}

func (r *mqlAlicloudVpcNetwork) id() (string, error) {
	return r.cacheRegion + "/" + r.VpcId.Data, nil
}

// vswitches lists the vSwitches that belong to this VPC, in the VPC's region.
func (r *mqlAlicloudVpcNetwork) vswitches() ([]any, error) {
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
		resp, err := client.DescribeVSwitches(&vpcclient.DescribeVSwitchesRequest{
			RegionId:   &r.cacheRegion,
			VpcId:      &r.cacheVpcID,
			PageNumber: &pageNumber,
			PageSize:   &pageSize,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.VSwitches == nil {
			break
		}

		for _, vsw := range resp.Body.VSwitches.VSwitch {
			if vsw == nil || vsw.VSwitchId == nil {
				continue
			}
			vswitch, err := newVpcVswitch(r.MqlRuntime, r.cacheRegion, vsw)
			if err != nil {
				return nil, err
			}
			res = append(res, vswitch)
		}

		if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// natGateways lists the NAT gateways that belong to this VPC, in the VPC's
// region.
func (r *mqlAlicloudVpcNetwork) natGateways() ([]any, error) {
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
		resp, err := client.DescribeNatGateways(&vpcclient.DescribeNatGatewaysRequest{
			RegionId:   &r.cacheRegion,
			VpcId:      &r.cacheVpcID,
			PageNumber: &pageNumber,
			PageSize:   &pageSize,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.NatGateways == nil {
			break
		}

		for _, nat := range resp.Body.NatGateways.NatGateway {
			if nat == nil || nat.NatGatewayId == nil {
				continue
			}
			natGateway, err := newVpcNatGateway(r.MqlRuntime, r.cacheRegion, nat)
			if err != nil {
				return nil, err
			}
			res = append(res, natGateway)
		}

		if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// routeTables lists the route tables that belong to this VPC, in the VPC's
// region.
func (r *mqlAlicloudVpcNetwork) routeTables() ([]any, error) {
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
		resp, err := client.DescribeRouteTableList(&vpcclient.DescribeRouteTableListRequest{
			RegionId:   &r.cacheRegion,
			VpcId:      &r.cacheVpcID,
			PageNumber: &pageNumber,
			PageSize:   &pageSize,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.RouterTableList == nil {
			break
		}

		for _, rt := range resp.Body.RouterTableList.RouterTableListType {
			if rt == nil || rt.RouteTableId == nil {
				continue
			}
			routeTable, err := newVpcRouteTable(r.MqlRuntime, r.cacheRegion, rt)
			if err != nil {
				return nil, err
			}
			res = append(res, routeTable)
		}

		if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

func (r *mqlAlicloudVpc) vswitches() ([]any, error) {
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
			req := &vpcclient.DescribeVSwitchesRequest{
				RegionId:   &region,
				PageNumber: &pageNumber,
				PageSize:   &pageSize,
			}
			resp, err := client.DescribeVSwitches(req)
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.VSwitches == nil {
				break
			}

			for _, vsw := range resp.Body.VSwitches.VSwitch {
				if vsw == nil || vsw.VSwitchId == nil {
					continue
				}
				vswitch, err := newVpcVswitch(r.MqlRuntime, region, vsw)
				if err != nil {
					return nil, err
				}
				res = append(res, vswitch)
			}

			if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// mqlAlicloudVpcVswitchInternal caches the region and owning VPC id (for the
// region-scoped __id and the typed vpc() reference) plus the associated route
// table and network ACL ids (for the typed routeTable() and networkAcl()
// references).
type mqlAlicloudVpcVswitchInternal struct {
	cacheRegion       string
	cacheVpcID        string
	cacheRouteTableID string
	cacheNetworkAclID string
}

// newVpcVswitch maps a DescribeVSwitches item into an alicloud.vpc.vswitch
// resource, shared by the list accessor and initAlicloudVpcVswitch.
func newVpcVswitch(runtime *plugin.Runtime, region string, vsw *vpcclient.DescribeVSwitchesResponseBodyVSwitchesVSwitch) (plugin.Resource, error) {
	var routeTableId, routeTableType *string
	if vsw.RouteTable != nil {
		routeTableId = vsw.RouteTable.RouteTableId
		routeTableType = vsw.RouteTable.RouteTableType
	}

	tags := map[string]any{}
	if vsw.Tags != nil {
		pairs := make([]*vpcTag, 0, len(vsw.Tags.Tag))
		for _, t := range vsw.Tags.Tag {
			if t != nil {
				pairs = append(pairs, &vpcTag{key: t.Key, value: t.Value})
			}
		}
		tags = vpcTagMap(pairs)
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.vswitch", map[string]*llx.RawData{
		"__id":                    llx.StringData(region + "/" + vpcStr(vsw.VSwitchId)),
		"vSwitchId":               llx.StringDataPtr(vsw.VSwitchId),
		"vSwitchName":             llx.StringDataPtr(vsw.VSwitchName),
		"description":             llx.StringDataPtr(vsw.Description),
		"cidrBlock":               llx.StringDataPtr(vsw.CidrBlock),
		"ipv6CidrBlock":           llx.StringDataPtr(vsw.Ipv6CidrBlock),
		"enabledIpv6":             llx.BoolDataPtr(vsw.EnabledIpv6),
		"status":                  llx.StringDataPtr(vsw.Status),
		"zoneId":                  llx.StringDataPtr(vsw.ZoneId),
		"availableIpAddressCount": llx.IntDataPtr(vsw.AvailableIpAddressCount),
		"isDefault":               llx.BoolDataPtr(vsw.IsDefault),
		"creationTime":            llx.TimeDataPtr(vpcParseTime(vsw.CreationTime)),
		"routeTableType":          llx.StringDataPtr(routeTableType),
		"resourceGroupId":         llx.StringDataPtr(vsw.ResourceGroupId),
		"shareType":               llx.StringDataPtr(vsw.ShareType),
		"ownerId":                 llx.IntDataPtr(vsw.OwnerId),
		"tags":                    llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	vswitch := resource.(*mqlAlicloudVpcVswitch)
	vswitch.cacheRegion = region
	vswitch.cacheVpcID = vpcStr(vsw.VpcId)
	vswitch.cacheRouteTableID = vpcStr(routeTableId)
	vswitch.cacheNetworkAclID = vpcStr(vsw.NetworkAclId)
	return vswitch, nil
}

func (r *mqlAlicloudVpcVswitch) id() (string, error) {
	return r.cacheRegion + "/" + r.VSwitchId.Data, nil
}

func (r *mqlAlicloudVpcVswitch) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudVpcVswitch) routeTable() (*mqlAlicloudVpcRouteTable, error) {
	if r.cacheRouteTableID == "" {
		r.RouteTable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcRouteTable(r.MqlRuntime, r.cacheRegion, r.cacheRouteTableID)
}

func (r *mqlAlicloudVpcVswitch) networkAcl() (*mqlAlicloudVpcNetworkAcl, error) {
	if r.cacheNetworkAclID == "" {
		r.NetworkAcl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetworkAcl(r.MqlRuntime, r.cacheRegion, r.cacheNetworkAclID)
}

func (r *mqlAlicloudVpc) routeTables() ([]any, error) {
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
			req := &vpcclient.DescribeRouteTableListRequest{
				RegionId:   &region,
				PageNumber: &pageNumber,
				PageSize:   &pageSize,
			}
			resp, err := client.DescribeRouteTableList(req)
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.RouterTableList == nil {
				break
			}

			for _, rt := range resp.Body.RouterTableList.RouterTableListType {
				if rt == nil || rt.RouteTableId == nil {
					continue
				}
				routeTable, err := newVpcRouteTable(r.MqlRuntime, region, rt)
				if err != nil {
					return nil, err
				}
				res = append(res, routeTable)
			}

			if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// mqlAlicloudVpcRouteTableInternal caches the region the route table was
// discovered in (so route entries can be fetched from the correct regional
// endpoint and the __id stays region-scoped), its owning VPC id (for the typed
// vpc() reference), and the ids of the vSwitches associated with it (for the
// typed vswitches() collection).
type mqlAlicloudVpcRouteTableInternal struct {
	cacheRegion     string
	cacheVpcID      string
	cacheVSwitchIDs []string

	routesLock        sync.Mutex
	routesFetched     atomic.Bool
	cacheRouteEntries []*vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry
}

// newVpcRouteTable maps a DescribeRouteTableList item into an
// alicloud.vpc.routeTable resource. It is shared by the namespace and network
// list accessors and by initAlicloudVpcRouteTable so every path produces a
// fully populated resource.
func newVpcRouteTable(runtime *plugin.Runtime, region string, rt *vpcclient.DescribeRouteTableListResponseBodyRouterTableListRouterTableListType) (plugin.Resource, error) {
	var vSwitchIDs []string
	if rt.VSwitchIds != nil {
		for _, s := range rt.VSwitchIds.VSwitchId {
			if s != nil {
				vSwitchIDs = append(vSwitchIDs, *s)
			}
		}
	}
	gatewayIds := []any{}
	if rt.GatewayIds != nil {
		gatewayIds = vpcStrSlice(rt.GatewayIds.GatewayIds)
	}

	tags := map[string]any{}
	if rt.Tags != nil {
		pairs := make([]*vpcTag, 0, len(rt.Tags.Tag))
		for _, t := range rt.Tags.Tag {
			if t != nil {
				pairs = append(pairs, &vpcTag{key: t.Key, value: t.Value})
			}
		}
		tags = vpcTagMap(pairs)
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.routeTable", map[string]*llx.RawData{
		"__id":                   llx.StringData(region + "/" + vpcStr(rt.RouteTableId)),
		"routeTableId":           llx.StringDataPtr(rt.RouteTableId),
		"routeTableName":         llx.StringDataPtr(rt.RouteTableName),
		"routeTableType":         llx.StringDataPtr(rt.RouteTableType),
		"description":            llx.StringDataPtr(rt.Description),
		"status":                 llx.StringDataPtr(rt.Status),
		"creationTime":           llx.TimeDataPtr(vpcParseTime(rt.CreationTime)),
		"resourceGroupId":        llx.StringDataPtr(rt.ResourceGroupId),
		"gatewayIds":             llx.ArrayData(gatewayIds, types.String),
		"associateType":          llx.StringDataPtr(rt.AssociateType),
		"routerId":               llx.StringDataPtr(rt.RouterId),
		"routerType":             llx.StringDataPtr(rt.RouterType),
		"routePropagationEnable": llx.BoolDataPtr(rt.RoutePropagationEnable),
		"ownerId":                llx.IntDataPtr(rt.OwnerId),
		"tags":                   llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlRt := resource.(*mqlAlicloudVpcRouteTable)
	mqlRt.cacheRegion = region
	mqlRt.cacheVpcID = vpcStr(rt.VpcId)
	mqlRt.cacheVSwitchIDs = vSwitchIDs
	return mqlRt, nil
}

func (r *mqlAlicloudVpcRouteTable) id() (string, error) {
	return r.cacheRegion + "/" + r.RouteTableId.Data, nil
}

func (r *mqlAlicloudVpcRouteTable) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

// vswitches resolves the vSwitches associated with this route table. The set is
// small and fixed (the ids are carried on the route table item), so each is
// resolved by id rather than by listing the whole region.
func (r *mqlAlicloudVpcRouteTable) vswitches() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVSwitchIDs {
		if id == "" {
			continue
		}
		vswitch, err := resolveVpcVswitch(r.MqlRuntime, r.cacheRegion, id)
		if err != nil {
			return nil, err
		}
		if vswitch != nil {
			res = append(res, vswitch)
		}
	}
	return res, nil
}

// fetchRouteEntries walks DescribeRouteEntryList and memoizes the raw entries.
// Both the deprecated routeEntries dict list and the typed routes list read
// through it, so querying them together costs one walk rather than two.
func (r *mqlAlicloudVpcRouteTable) fetchRouteEntries() ([]*vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry, error) {
	if r.routesFetched.Load() {
		return r.cacheRouteEntries, nil
	}
	r.routesLock.Lock()
	defer r.routesLock.Unlock()
	if r.routesFetched.Load() {
		return r.cacheRouteEntries, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	region := r.cacheRegion
	if region == "" {
		// The route table was not created through the regional fan-out, so the
		// region needed to reach the route-entry endpoint is unknown.
		return nil, fmt.Errorf("alicloud.vpc.routeTable: region unknown for route table %s", r.RouteTableId.Data)
	}
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, err
	}

	entries := []*vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry{}
	var nextToken *string
	maxResult := int32(100)
	for {
		req := &vpcclient.DescribeRouteEntryListRequest{
			RegionId:     &region,
			RouteTableId: &r.RouteTableId.Data,
			MaxResult:    &maxResult,
			NextToken:    nextToken,
		}
		resp, err := client.DescribeRouteEntryList(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.RouteEntrys == nil {
			break
		}

		for _, entry := range resp.Body.RouteEntrys.RouteEntry {
			if entry == nil {
				continue
			}
			entries = append(entries, entry)
		}

		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = resp.Body.NextToken
	}

	r.cacheRouteEntries = entries
	r.routesFetched.Store(true)
	return r.cacheRouteEntries, nil
}

// routeEntryNextHop returns the first next hop of a route entry. The API models
// next hops as a list, but a route hands traffic to exactly one, so the rest
// (when present at all) are weighted alternates that do not change where the
// route leads.
func routeEntryNextHop(entry *vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry) (nextHopType, nextHopID string) {
	if entry == nil || entry.NextHops == nil {
		return "", ""
	}
	for _, h := range entry.NextHops.NextHop {
		if h == nil {
			continue
		}
		return vpcStr(h.NextHopType), vpcStr(h.NextHopId)
	}
	return "", ""
}

func (r *mqlAlicloudVpcRouteTable) routeEntries() ([]any, error) {
	entries, err := r.fetchRouteEntries()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, entry := range entries {
		nextHopType, nextHopID := routeEntryNextHop(entry)
		res = append(res, map[string]any{
			"routeEntryId":         vpcStr(entry.RouteEntryId),
			"routeEntryName":       vpcStr(entry.RouteEntryName),
			"description":          vpcStr(entry.Description),
			"destinationCidrBlock": vpcStr(entry.DestinationCidrBlock),
			"nextHopType":          nextHopType,
			"nextHopId":            nextHopID,
			"status":               vpcStr(entry.Status),
			"type":                 vpcStr(entry.Type),
			"ipVersion":            vpcStr(entry.IpVersion),
			"origin":               vpcStr(entry.Origin),
		})
	}
	return res, nil
}

func (r *mqlAlicloudVpcRouteTable) routes() ([]any, error) {
	entries, err := r.fetchRouteEntries()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, entry := range entries {
		nextHopType, nextHopID := routeEntryNextHop(entry)
		routeID := vpcStr(entry.RouteEntryId)
		if routeID == "" {
			// A system route can arrive without an id; key it on the route table
			// and destination, which is unique within the table.
			routeID = r.RouteTableId.Data + "/" + vpcStr(entry.DestinationCidrBlock)
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.routeTable.route", map[string]*llx.RawData{
			"__id":                 llx.StringData(r.RouteTableId.Data + "/" + routeID),
			"routeEntryId":         llx.StringDataPtr(entry.RouteEntryId),
			"routeEntryName":       llx.StringDataPtr(entry.RouteEntryName),
			"description":          llx.StringDataPtr(entry.Description),
			"destinationCidrBlock": llx.StringDataPtr(entry.DestinationCidrBlock),
			"nextHopType":          llx.StringData(nextHopType),
			"nextHopId":            llx.StringData(nextHopID),
			"status":               llx.StringDataPtr(entry.Status),
			"type":                 llx.StringDataPtr(entry.Type),
			"ipVersion":            llx.StringDataPtr(entry.IpVersion),
			"origin":               llx.StringDataPtr(entry.Origin),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (r *mqlAlicloudVpc) natGateways() ([]any, error) {
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
			req := &vpcclient.DescribeNatGatewaysRequest{
				RegionId:   &region,
				PageNumber: &pageNumber,
				PageSize:   &pageSize,
			}
			resp, err := client.DescribeNatGateways(req)
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.NatGateways == nil {
				break
			}

			for _, nat := range resp.Body.NatGateways.NatGateway {
				if nat == nil || nat.NatGatewayId == nil {
					continue
				}
				natGateway, err := newVpcNatGateway(r.MqlRuntime, region, nat)
				if err != nil {
					return nil, err
				}
				res = append(res, natGateway)
			}

			if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// newVpcNatGateway maps a DescribeNatGateways item into an
// alicloud.vpc.natGateway resource. It is shared by the namespace and network
// list accessors.
func newVpcNatGateway(runtime *plugin.Runtime, region string, nat *vpcclient.DescribeNatGatewaysResponseBodyNatGatewaysNatGateway) (plugin.Resource, error) {
	snatTableIds := []any{}
	if nat.SnatTableIds != nil {
		snatTableIds = vpcStrSlice(nat.SnatTableIds.SnatTableId)
	}
	forwardTableIds := []any{}
	if nat.ForwardTableIds != nil {
		forwardTableIds = vpcStrSlice(nat.ForwardTableIds.ForwardTableId)
	}
	fullNatTableIds := []any{}
	if nat.FullNatTableIds != nil {
		fullNatTableIds = vpcStrSlice(nat.FullNatTableIds.FullNatTableId)
	}

	var privateInfo any
	if nat.NatGatewayPrivateInfo != nil {
		pi := nat.NatGatewayPrivateInfo
		privateInfo = map[string]any{
			"vswitchId":               vpcStr(pi.VswitchId),
			"privateIpAddress":        vpcStr(pi.PrivateIpAddress),
			"eniInstanceId":           vpcStr(pi.EniInstanceId),
			"eniType":                 vpcStr(pi.EniType),
			"izNo":                    vpcStr(pi.IzNo),
			"maxBandwidth":            vpcInt32(pi.MaxBandwidth),
			"maxSessionEstablishRate": vpcInt32(pi.MaxSessionEstablishRate),
			"maxSessionQuota":         vpcInt32(pi.MaxSessionQuota),
		}
	}

	var accessMode any
	if nat.AccessMode != nil {
		accessMode = map[string]any{
			"modeValue":  vpcStr(nat.AccessMode.ModeValue),
			"tunnelType": vpcStr(nat.AccessMode.TunnelType),
		}
	}

	ipLists := []any{}
	if nat.IpLists != nil {
		for _, ip := range nat.IpLists.IpList {
			if ip == nil {
				continue
			}
			ipLists = append(ipLists, map[string]any{
				"allocationId":     vpcStr(ip.AllocationId),
				"ipAddress":        vpcStr(ip.IpAddress),
				"privateIpAddress": vpcStr(ip.PrivateIpAddress),
				"snatEntryEnabled": vpcBool(ip.SnatEntryEnabled),
				"usingStatus":      vpcStr(ip.UsingStatus),
			})
		}
	}

	tags := map[string]any{}
	if nat.Tags != nil {
		pairs := make([]*vpcTag, 0, len(nat.Tags.Tag))
		for _, t := range nat.Tags.Tag {
			if t != nil {
				pairs = append(pairs, &vpcTag{key: t.TagKey, value: t.TagValue})
			}
		}
		tags = vpcTagMap(pairs)
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.natGateway", map[string]*llx.RawData{
		"__id":                      llx.StringData(region + "/" + vpcStr(nat.NatGatewayId)),
		"natGatewayId":              llx.StringDataPtr(nat.NatGatewayId),
		"name":                      llx.StringDataPtr(nat.Name),
		"description":               llx.StringDataPtr(nat.Description),
		"status":                    llx.StringDataPtr(nat.Status),
		"spec":                      llx.StringDataPtr(nat.Spec),
		"natType":                   llx.StringDataPtr(nat.NatType),
		"networkType":               llx.StringDataPtr(nat.NetworkType),
		"businessStatus":            llx.StringDataPtr(nat.BusinessStatus),
		"creationTime":              llx.TimeDataPtr(vpcParseTime(nat.CreationTime)),
		"expiredTime":               llx.TimeDataPtr(vpcParseTime(nat.ExpiredTime)),
		"internetChargeType":        llx.StringDataPtr(nat.InternetChargeType),
		"instanceChargeType":        llx.StringDataPtr(nat.InstanceChargeType),
		"deletionProtection":        llx.BoolDataPtr(nat.DeletionProtection),
		"ecsMetricEnabled":          llx.BoolDataPtr(nat.EcsMetricEnabled),
		"icmpReplyEnabled":          llx.BoolDataPtr(nat.IcmpReplyEnabled),
		"privateLinkEnabled":        llx.BoolDataPtr(nat.PrivateLinkEnabled),
		"privateLinkMode":           llx.StringDataPtr(nat.PrivateLinkMode),
		"securityProtectionEnabled": llx.BoolDataPtr(nat.SecurityProtectionEnabled),
		"eipBindMode":               llx.StringDataPtr(nat.EipBindMode),
		"enableSessionLog":          llx.StringDataPtr(nat.EnableSessionLog),
		"autoPay":                   llx.BoolDataPtr(nat.AutoPay),
		"regionId":                  llx.StringDataPtr(nat.RegionId),
		"resourceGroupId":           llx.StringDataPtr(nat.ResourceGroupId),
		"snatTableIds":              llx.ArrayData(snatTableIds, types.String),
		"forwardTableIds":           llx.ArrayData(forwardTableIds, types.String),
		"fullNatTableIds":           llx.ArrayData(fullNatTableIds, types.String),
		"natGatewayPrivateInfo":     llx.DictData(privateInfo),
		"ipLists":                   llx.ArrayData(ipLists, types.Dict),
		"accessMode":                llx.DictData(accessMode),
		"tags":                      llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlNat := resource.(*mqlAlicloudVpcNatGateway)
	mqlNat.cacheRegion = region
	mqlNat.cacheVpcID = vpcStr(nat.VpcId)
	return mqlNat, nil
}

// mqlAlicloudVpcNatGatewayInternal caches the region and owning VPC id so the
// NAT gateway exposes a region-scoped __id and a typed vpc() reference.
type mqlAlicloudVpcNatGatewayInternal struct {
	cacheRegion string
	cacheVpcID  string
}

func (r *mqlAlicloudVpcNatGateway) id() (string, error) {
	return r.cacheRegion + "/" + r.NatGatewayId.Data, nil
}

func (r *mqlAlicloudVpcNatGateway) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudVpc) eipAddresses() ([]any, error) {
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
			req := &vpcclient.DescribeEipAddressesRequest{
				RegionId:   &region,
				PageNumber: &pageNumber,
				PageSize:   &pageSize,
			}
			resp, err := client.DescribeEipAddresses(req)
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.EipAddresses == nil {
				break
			}

			for _, eip := range resp.Body.EipAddresses.EipAddress {
				if eip == nil || eip.AllocationId == nil {
					continue
				}

				securityProtectionTypes := []any{}
				if eip.SecurityProtectionTypes != nil {
					securityProtectionTypes = vpcStrSlice(eip.SecurityProtectionTypes.SecurityProtectionType)
				}

				tags := map[string]any{}
				if eip.Tags != nil {
					pairs := make([]*vpcTag, 0, len(eip.Tags.Tag))
					for _, t := range eip.Tags.Tag {
						if t != nil {
							pairs = append(pairs, &vpcTag{key: t.Key, value: t.Value})
						}
					}
					tags = vpcTagMap(pairs)
				}

				eipAddress, err := CreateResource(r.MqlRuntime, "alicloud.vpc.eipAddress", map[string]*llx.RawData{
					"__id":                      llx.StringData(region + "/" + vpcStr(eip.AllocationId)),
					"allocationId":              llx.StringDataPtr(eip.AllocationId),
					"name":                      llx.StringDataPtr(eip.Name),
					"description":               llx.StringDataPtr(eip.Description),
					"ipAddress":                 llx.StringDataPtr(eip.IpAddress),
					"status":                    llx.StringDataPtr(eip.Status),
					"bandwidth":                 llx.StringDataPtr(eip.Bandwidth),
					"internetChargeType":        llx.StringDataPtr(eip.InternetChargeType),
					"chargeType":                llx.StringDataPtr(eip.ChargeType),
					"isp":                       llx.StringDataPtr(eip.ISP),
					"instanceId":                llx.StringDataPtr(eip.InstanceId),
					"instanceType":              llx.StringDataPtr(eip.InstanceType),
					"instanceRegionId":          llx.StringDataPtr(eip.InstanceRegionId),
					"privateIpAddress":          llx.StringDataPtr(eip.PrivateIpAddress),
					"allocationTime":            llx.TimeDataPtr(vpcParseTime(eip.AllocationTime)),
					"expiredTime":               llx.TimeDataPtr(vpcParseTime(eip.ExpiredTime)),
					"hdMonitorStatus":           llx.StringDataPtr(eip.HDMonitorStatus),
					"deletionProtection":        llx.BoolDataPtr(eip.DeletionProtection),
					"hasReservationData":        llx.StringDataPtr(eip.HasReservationData),
					"netmode":                   llx.StringDataPtr(eip.Netmode),
					"publicIpAddressPoolId":     llx.StringDataPtr(eip.PublicIpAddressPoolId),
					"regionId":                  llx.StringDataPtr(eip.RegionId),
					"resourceGroupId":           llx.StringDataPtr(eip.ResourceGroupId),
					"zone":                      llx.StringDataPtr(eip.Zone),
					"bandwidthPackageId":        llx.StringDataPtr(eip.BandwidthPackageId),
					"bandwidthPackageType":      llx.StringDataPtr(eip.BandwidthPackageType),
					"bandwidthPackageBandwidth": llx.StringDataPtr(eip.BandwidthPackageBandwidth),
					"eipBandwidth":              llx.StringDataPtr(eip.EipBandwidth),
					"bizType":                   llx.StringDataPtr(eip.BizType),
					"businessStatus":            llx.StringDataPtr(eip.BusinessStatus),
					"mode":                      llx.StringDataPtr(eip.Mode),
					"secondLimited":             llx.BoolDataPtr(eip.SecondLimited),
					"segmentInstanceId":         llx.StringDataPtr(eip.SegmentInstanceId),
					"securityProtectionTypes":   llx.ArrayData(securityProtectionTypes, types.String),
					"serviceManaged":            llx.IntDataPtr(eip.ServiceManaged),
					"tags":                      llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				mqlEip := eipAddress.(*mqlAlicloudVpcEipAddress)
				mqlEip.cacheRegion = region
				mqlEip.cacheVpcID = vpcStr(eip.VpcId)
				res = append(res, eipAddress)
			}

			if resp.Body.TotalCount == nil || int64(pageNumber)*int64(pageSize) >= int64(*resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// mqlAlicloudVpcEipAddressInternal caches the region the EIP was discovered in
// (so its region-scoped __id can be reconstructed) and its bound VPC id (for
// the typed vpc() reference).
type mqlAlicloudVpcEipAddressInternal struct {
	cacheRegion string
	cacheVpcID  string
}

func (r *mqlAlicloudVpcEipAddress) id() (string, error) {
	return r.cacheRegion + "/" + r.AllocationId.Data, nil
}

func (r *mqlAlicloudVpcEipAddress) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudVpc) networkAcls() ([]any, error) {
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
			req := &vpcclient.DescribeNetworkAclsRequest{
				RegionId:   &region,
				PageNumber: &pageNumber,
				PageSize:   &pageSize,
			}
			resp, err := client.DescribeNetworkAcls(req)
			if err != nil {
				// a region may be un-activated or access-denied; skip it rather than failing the whole scan
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.NetworkAcls == nil {
				break
			}

			for _, acl := range resp.Body.NetworkAcls.NetworkAcl {
				if acl == nil || acl.NetworkAclId == nil {
					continue
				}
				networkAcl, err := newVpcNetworkAcl(r.MqlRuntime, region, acl)
				if err != nil {
					return nil, err
				}
				res = append(res, networkAcl)
			}

			total := vpcAclTotalCount(resp.Body.TotalCount)
			if total < 0 || int64(pageNumber)*int64(pageSize) >= total {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// newVpcNetworkAcl maps a DescribeNetworkAcls item into an
// alicloud.vpc.networkAcl resource. It is shared by the namespace list accessor
// and by initAlicloudVpcNetworkAcl.
// vpcNetworkAclEntryArgs carries one rule's fields. Ingress and egress rules are
// separate SDK types that differ only in whether they name a source or a
// destination, so one builder covers both.
type vpcNetworkAclEntryArgs struct {
	entryID           *string
	name              *string
	description       *string
	protocol          *string
	port              *string
	sourceCidrIp      *string
	destinationCidrIp *string
	policy            *string
	entryType         *string
	ipVersion         *string
}

// vpcNetworkAclEntryKey builds the per-ACL part of a rule's cache key. The rule
// id is used when the API returns one. A rule without an id falls back to the
// fields that make it distinct within its ACL, because keying every id-less rule
// on the ACL alone would collapse them onto one another.
func vpcNetworkAclEntryKey(direction string, args vpcNetworkAclEntryArgs) string {
	if id := vpcStr(args.entryID); id != "" {
		return id
	}
	return direction + "/" + vpcStr(args.protocol) + "/" + vpcStr(args.port) + "/" +
		vpcStr(args.sourceCidrIp) + vpcStr(args.destinationCidrIp)
}

// newVpcNetworkAclEntry builds one alicloud.vpc.networkAcl.entry, keyed by its
// ACL so two ACLs holding equivalent rules stay distinct.
func newVpcNetworkAclEntry(runtime *plugin.Runtime, aclID, direction string, args vpcNetworkAclEntryArgs) (plugin.Resource, error) {
	entryID := vpcStr(args.entryID)
	key := vpcNetworkAclEntryKey(direction, args)
	fromPort, toPort := portRangeBounds(vpcStr(args.port))
	return CreateResource(runtime, "alicloud.vpc.networkAcl.entry", map[string]*llx.RawData{
		"__id":              llx.StringData(aclID + "/" + key),
		"entryId":           llx.StringData(entryID),
		"name":              llx.StringDataPtr(args.name),
		"description":       llx.StringDataPtr(args.description),
		"direction":         llx.StringData(direction),
		"policy":            llx.StringDataPtr(args.policy),
		"protocol":          llx.StringDataPtr(args.protocol),
		"port":              llx.StringDataPtr(args.port),
		"fromPort":          llx.IntDataPtr(fromPort),
		"toPort":            llx.IntDataPtr(toPort),
		"sourceCidrIp":      llx.StringData(vpcStr(args.sourceCidrIp)),
		"destinationCidrIp": llx.StringData(vpcStr(args.destinationCidrIp)),
		"entryType":         llx.StringDataPtr(args.entryType),
		"ipVersion":         llx.StringDataPtr(args.ipVersion),
	})
}

func newVpcNetworkAcl(runtime *plugin.Runtime, region string, acl *vpcclient.DescribeNetworkAclsResponseBodyNetworkAclsNetworkAcl) (plugin.Resource, error) {
	ingress := []any{}
	if acl.IngressAclEntries != nil {
		for _, e := range acl.IngressAclEntries.IngressAclEntry {
			if e == nil {
				continue
			}
			ingress = append(ingress, map[string]any{
				"networkAclEntryId":   vpcStr(e.NetworkAclEntryId),
				"networkAclEntryName": vpcStr(e.NetworkAclEntryName),
				"description":         vpcStr(e.Description),
				"protocol":            vpcStr(e.Protocol),
				"port":                vpcStr(e.Port),
				"sourceCidrIp":        vpcStr(e.SourceCidrIp),
				"policy":              vpcStr(e.Policy),
				"entryType":           vpcStr(e.EntryType),
				"ipVersion":           vpcStr(e.IpVersion),
			})
		}
	}

	egress := []any{}
	if acl.EgressAclEntries != nil {
		for _, e := range acl.EgressAclEntries.EgressAclEntry {
			if e == nil {
				continue
			}
			egress = append(egress, map[string]any{
				"networkAclEntryId":   vpcStr(e.NetworkAclEntryId),
				"networkAclEntryName": vpcStr(e.NetworkAclEntryName),
				"description":         vpcStr(e.Description),
				"protocol":            vpcStr(e.Protocol),
				"port":                vpcStr(e.Port),
				"destinationCidrIp":   vpcStr(e.DestinationCidrIp),
				"policy":              vpcStr(e.Policy),
				"entryType":           vpcStr(e.EntryType),
				"ipVersion":           vpcStr(e.IpVersion),
			})
		}
	}

	resources := []any{}
	if acl.Resources != nil {
		for _, rsc := range acl.Resources.Resource {
			if rsc == nil {
				continue
			}
			resources = append(resources, map[string]any{
				"resourceId":   vpcStr(rsc.ResourceId),
				"resourceType": vpcStr(rsc.ResourceType),
				"status":       vpcStr(rsc.Status),
			})
		}
	}

	tags := map[string]any{}
	if acl.Tags != nil {
		pairs := make([]*vpcTag, 0, len(acl.Tags.Tag))
		for _, t := range acl.Tags.Tag {
			if t != nil {
				pairs = append(pairs, &vpcTag{key: t.Key, value: t.Value})
			}
		}
		tags = vpcTagMap(pairs)
	}

	aclID := vpcStr(acl.NetworkAclId)

	// The rule bodies are already in this response, so the typed entries are
	// built alongside the dict form rather than costing a second call.
	ingressEntries := []any{}
	if acl.IngressAclEntries != nil {
		for _, e := range acl.IngressAclEntries.IngressAclEntry {
			if e == nil {
				continue
			}
			entry, err := newVpcNetworkAclEntry(runtime, aclID, "ingress", vpcNetworkAclEntryArgs{
				entryID:      e.NetworkAclEntryId,
				name:         e.NetworkAclEntryName,
				description:  e.Description,
				protocol:     e.Protocol,
				port:         e.Port,
				sourceCidrIp: e.SourceCidrIp,
				policy:       e.Policy,
				entryType:    e.EntryType,
				ipVersion:    e.IpVersion,
			})
			if err != nil {
				return nil, err
			}
			ingressEntries = append(ingressEntries, entry)
		}
	}

	egressEntries := []any{}
	if acl.EgressAclEntries != nil {
		for _, e := range acl.EgressAclEntries.EgressAclEntry {
			if e == nil {
				continue
			}
			entry, err := newVpcNetworkAclEntry(runtime, aclID, "egress", vpcNetworkAclEntryArgs{
				entryID:           e.NetworkAclEntryId,
				name:              e.NetworkAclEntryName,
				description:       e.Description,
				protocol:          e.Protocol,
				port:              e.Port,
				destinationCidrIp: e.DestinationCidrIp,
				policy:            e.Policy,
				entryType:         e.EntryType,
				ipVersion:         e.IpVersion,
			})
			if err != nil {
				return nil, err
			}
			egressEntries = append(egressEntries, entry)
		}
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.networkAcl", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + aclID),
		"networkAclId":      llx.StringDataPtr(acl.NetworkAclId),
		"networkAclName":    llx.StringDataPtr(acl.NetworkAclName),
		"description":       llx.StringDataPtr(acl.Description),
		"status":            llx.StringDataPtr(acl.Status),
		"creationTime":      llx.TimeDataPtr(vpcParseTime(acl.CreationTime)),
		"regionId":          llx.StringDataPtr(acl.RegionId),
		"ownerId":           llx.IntDataPtr(acl.OwnerId),
		"ingressAclEntries": llx.ArrayData(ingress, types.Dict),
		"egressAclEntries":  llx.ArrayData(egress, types.Dict),
		"ingressEntries":    llx.ArrayData(ingressEntries, types.Resource("alicloud.vpc.networkAcl.entry")),
		"egressEntries":     llx.ArrayData(egressEntries, types.Resource("alicloud.vpc.networkAcl.entry")),
		"resources":         llx.ArrayData(resources, types.Dict),
		"tags":              llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlAcl := resource.(*mqlAlicloudVpcNetworkAcl)
	mqlAcl.cacheRegion = region
	mqlAcl.cacheVpcID = vpcStr(acl.VpcId)
	return mqlAcl, nil
}

// mqlAlicloudVpcNetworkAclInternal caches the region and owning VPC id so the
// network ACL exposes a region-scoped __id and a typed vpc() reference.
type mqlAlicloudVpcNetworkAclInternal struct {
	cacheRegion string
	cacheVpcID  string
}

func (r *mqlAlicloudVpcNetworkAcl) id() (string, error) {
	return r.cacheRegion + "/" + r.NetworkAclId.Data, nil
}

func (r *mqlAlicloudVpcNetworkAcl) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}
