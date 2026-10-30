// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// resolveVpcNetwork returns the typed VPC network for a native vpc id within a
// region, or (nil, nil) when vpcID is empty (the caller sets StateIsNull). The
// underlying init reuses an already-listed network from the resource cache and
// otherwise fetches it via DescribeVpcs.
func resolveVpcNetwork(runtime *plugin.Runtime, region, vpcID string) (*mqlAlicloudVpcNetwork, error) {
	if vpcID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.vpc.network", map[string]*llx.RawData{
		"vpcId":    llx.StringData(vpcID),
		"regionId": llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudVpcNetwork), nil
}

// resolveVpcVswitch is the vSwitch equivalent of resolveVpcNetwork.
func resolveVpcVswitch(runtime *plugin.Runtime, region, vswitchID string) (*mqlAlicloudVpcVswitch, error) {
	if vswitchID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.vpc.vswitch", map[string]*llx.RawData{
		"vSwitchId": llx.StringData(vswitchID),
		"regionId":  llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudVpcVswitch), nil
}

// resolveVpcNatGateway returns the typed NAT gateway for a native gateway id
// within a region, or (nil, nil) when natGatewayID is empty (the caller sets
// StateIsNull). The underlying init reuses an already-listed gateway from the
// resource cache and otherwise fetches it via DescribeNatGateways.
func resolveVpcNatGateway(runtime *plugin.Runtime, region, natGatewayID string) (*mqlAlicloudVpcNatGateway, error) {
	if natGatewayID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.vpc.natGateway", map[string]*llx.RawData{
		"natGatewayId": llx.StringData(natGatewayID),
		"regionId":     llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudVpcNatGateway), nil
}

// initAlicloudVpcNatGateway resolves a NAT gateway by its native id within a
// region. It backs both direct lookups and the typed natGateway() reference,
// reusing the cached instance when the gateway has already been listed.
func initAlicloudVpcNatGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	natGatewayID, err := requiredStringArg(args, "natGatewayId", "alicloud.vpc.natGateway")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.vpc.natGateway")
	if err != nil {
		return nil, nil, err
	}

	key := region + "/" + natGatewayID
	if x, ok := runtime.Resources.Get("alicloud.vpc.natGateway\x00" + key); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeNatGateways(&vpcclient.DescribeNatGatewaysRequest{
		RegionId:     &region,
		NatGatewayId: &natGatewayID,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.NatGateways != nil {
		for _, nat := range resp.Body.NatGateways.NatGateway {
			if nat == nil || nat.NatGatewayId == nil || *nat.NatGatewayId != natGatewayID {
				continue
			}
			res, err := newVpcNatGateway(runtime, region, nat)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.vpc.natGateway %q not found in region %q", natGatewayID, region)
}

// resolveVpcRouteTable returns the typed route table for a native route table id
// within a region, or (nil, nil) when routeTableID is empty.
func resolveVpcRouteTable(runtime *plugin.Runtime, region, routeTableID string) (*mqlAlicloudVpcRouteTable, error) {
	if routeTableID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.vpc.routeTable", map[string]*llx.RawData{
		"routeTableId": llx.StringData(routeTableID),
		"regionId":     llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudVpcRouteTable), nil
}

// resolveVpcNetworkAcl returns the typed network ACL for a native network ACL id
// within a region, or (nil, nil) when networkAclID is empty.
func resolveVpcNetworkAcl(runtime *plugin.Runtime, region, networkAclID string) (*mqlAlicloudVpcNetworkAcl, error) {
	if networkAclID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.vpc.networkAcl", map[string]*llx.RawData{
		"networkAclId": llx.StringData(networkAclID),
		"regionId":     llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudVpcNetworkAcl), nil
}

// initAlicloudVpcNetwork resolves a VPC network by its native vpc id within a
// region. It backs both direct lookups and typed vpc() cross-references, reusing
// the cached instance when the network has already been listed.
func initAlicloudVpcNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	args = scopedInitArgs(runtime, args, connection.OptionVpcID, "vpcId")

	vpcID, err := requiredStringArg(args, "vpcId", "alicloud.vpc.network")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.vpc.network")
	if err != nil {
		return nil, nil, err
	}

	key := region + "/" + vpcID
	if x, ok := runtime.Resources.Get("alicloud.vpc.network\x00" + key); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeVpcs(&vpcclient.DescribeVpcsRequest{
		RegionId: &region,
		VpcId:    &vpcID,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.Vpcs != nil {
		for _, vpc := range resp.Body.Vpcs.Vpc {
			if vpc == nil || vpc.VpcId == nil || *vpc.VpcId != vpcID {
				continue
			}
			res, err := newVpcNetwork(runtime, region, vpc)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.vpc.network %q not found in region %q", vpcID, region)
}

// initAlicloudVpcVswitch resolves a vSwitch by its native id within a region. It
// backs both direct lookups and typed vswitch() cross-references, reusing the
// cached instance when the vSwitch has already been listed.
func initAlicloudVpcVswitch(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	vswitchID, err := requiredStringArg(args, "vSwitchId", "alicloud.vpc.vswitch")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.vpc.vswitch")
	if err != nil {
		return nil, nil, err
	}

	key := region + "/" + vswitchID
	if x, ok := runtime.Resources.Get("alicloud.vpc.vswitch\x00" + key); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeVSwitches(&vpcclient.DescribeVSwitchesRequest{
		RegionId:  &region,
		VSwitchId: &vswitchID,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.VSwitches != nil {
		for _, vsw := range resp.Body.VSwitches.VSwitch {
			if vsw == nil || vsw.VSwitchId == nil || *vsw.VSwitchId != vswitchID {
				continue
			}
			res, err := newVpcVswitch(runtime, region, vsw)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.vpc.vswitch %q not found in region %q", vswitchID, region)
}

// initAlicloudVpcRouteTable resolves a route table by its native id within a
// region. It backs both direct lookups and the typed routeTable() reference,
// reusing the cached instance when the route table has already been listed.
func initAlicloudVpcRouteTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	routeTableID, err := requiredStringArg(args, "routeTableId", "alicloud.vpc.routeTable")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.vpc.routeTable")
	if err != nil {
		return nil, nil, err
	}

	key := region + "/" + routeTableID
	if x, ok := runtime.Resources.Get("alicloud.vpc.routeTable\x00" + key); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeRouteTableList(&vpcclient.DescribeRouteTableListRequest{
		RegionId:     &region,
		RouteTableId: &routeTableID,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.RouterTableList != nil {
		for _, rt := range resp.Body.RouterTableList.RouterTableListType {
			if rt == nil || rt.RouteTableId == nil || *rt.RouteTableId != routeTableID {
				continue
			}
			res, err := newVpcRouteTable(runtime, region, rt)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.vpc.routeTable %q not found in region %q", routeTableID, region)
}

// initAlicloudVpcNetworkAcl resolves a network ACL by its native id within a
// region. It backs both direct lookups and the typed networkAcl() reference,
// reusing the cached instance when the network ACL has already been listed.
func initAlicloudVpcNetworkAcl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	networkAclID, err := requiredStringArg(args, "networkAclId", "alicloud.vpc.networkAcl")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.vpc.networkAcl")
	if err != nil {
		return nil, nil, err
	}

	key := region + "/" + networkAclID
	if x, ok := runtime.Resources.Get("alicloud.vpc.networkAcl\x00" + key); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeNetworkAcls(&vpcclient.DescribeNetworkAclsRequest{
		RegionId:     &region,
		NetworkAclId: &networkAclID,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.NetworkAcls != nil {
		for _, acl := range resp.Body.NetworkAcls.NetworkAcl {
			if acl == nil || acl.NetworkAclId == nil || *acl.NetworkAclId != networkAclID {
				continue
			}
			res, err := newVpcNetworkAcl(runtime, region, acl)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.vpc.networkAcl %q not found in region %q", networkAclID, region)
}

// scopedInitArgs backfills a singular resource's identifying arguments from the
// connection scope when the resource is invoked bare (no arguments) on a
// discovered child asset. Fine-grained discovery pins the object id under
// scopeOption and its region under OptionRegions, so `alicloud.cs.cluster` (and
// the ALB/NLB/VPC/WAF equivalents) resolve to the asset they are scanned against
// without the caller naming an id. When the caller supplied arguments, or the
// asset is not scoped to this object kind (for example the account root), the
// original args are returned unchanged and the resource's normal by-id lookup or
// required-argument error applies.
func scopedInitArgs(runtime *plugin.Runtime, args map[string]*llx.RawData, scopeOption, idField string) map[string]*llx.RawData {
	if len(args) != 0 {
		return args
	}
	conn := runtime.Connection.(*connection.AlicloudConnection)
	id, region, ok := conn.ScopedObject(scopeOption)
	if !ok {
		return args
	}
	return map[string]*llx.RawData{
		idField:    llx.StringData(id),
		"regionId": llx.StringData(region),
	}
}

// scopedInitIDArgs is the single-identifier form of scopedInitArgs, for
// resources whose init takes only an id and no region of its own.
func scopedInitIDArgs(runtime *plugin.Runtime, args map[string]*llx.RawData, scopeOption, idField string) map[string]*llx.RawData {
	if len(args) != 0 {
		return args
	}
	conn := runtime.Connection.(*connection.AlicloudConnection)
	id, _, ok := conn.ScopedObject(scopeOption)
	if !ok {
		return args
	}
	return map[string]*llx.RawData{idField: llx.StringData(id)}
}

// resourceManagerResource returns the shared alicloud.resourceManager instance.
// It memoizes the account's resource group listing, so every resourceGroup
// reference in a scan resolves against one ListResourceGroups call.
func resourceManagerResource(runtime *plugin.Runtime) (*mqlAlicloudResourceManager, error) {
	res, err := CreateResource(runtime, "alicloud.resourceManager", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudResourceManager), nil
}

// resolveResourceGroup returns the resource group that owns a resource, given
// the resource's resource group id.
//
// A resource group that cannot be read resolves to null rather than failing the
// caller: Resource Management is a separate service that an account may not
// have permission for, and one unreadable group must not fail a query over
// every instance in a region. The lookup is warned once per resource so the
// null is attributable, and alicloud.resourceManager.resourceGroups still
// surfaces the underlying error for anyone querying the groups directly.
func resolveResourceGroup(runtime *plugin.Runtime, groupID string, field *plugin.TValue[*mqlAlicloudResourceManagerResourceGroup]) (*mqlAlicloudResourceManagerResourceGroup, error) {
	if groupID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	rm, err := resourceManagerResource(runtime)
	if err != nil {
		log.Warn().Err(err).Str("resourceGroupId", groupID).
			Msg("alicloud> unable to reach the resource manager")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	group, err := rm.resourceGroupByID(groupID)
	if err != nil {
		log.Warn().Err(err).Str("resourceGroupId", groupID).
			Msg("alicloud> unable to resolve resource group")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if group == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return group, nil
}

// requiredStringArg reads a required non-empty string argument from an init
// args map, returning a descriptive error when it is missing or blank.
func requiredStringArg(args map[string]*llx.RawData, name, resource string) (string, error) {
	raw, ok := args[name]
	if !ok {
		return "", errors.New(resource + " requires a " + name + " to look up")
	}
	v, ok := raw.Value.(string)
	if !ok || v == "" {
		return "", errors.New(resource + " requires a " + name + " to look up")
	}
	return v, nil
}
