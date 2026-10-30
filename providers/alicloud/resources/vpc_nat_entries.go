// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	tea "github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// natEntryPageSize is the page size used for the NAT gateway rule listings.
const natEntryPageSize = 50

// natForwardsAllPorts reports whether a DNAT rule maps the whole port range
// rather than one port. The API writes that as the literal "any", and the rule
// then publishes every listening service on the private address rather than the
// one that was meant to be exposed.
func natForwardsAllPorts(externalPort, internalPort *string) bool {
	return natPortIsAny(externalPort) || natPortIsAny(internalPort)
}

// natPortIsAny reports whether a NAT port value names the whole range.
func natPortIsAny(port *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(port)), "any")
}

// mqlAlicloudVpcNatGatewaySnatEntryInternal caches the region and vSwitch the
// rule is scoped to, for the typed sourceVswitch() reference.
type mqlAlicloudVpcNatGatewaySnatEntryInternal struct {
	region          string
	sourceVSwitchID string
}

func (r *mqlAlicloudVpcNatGatewaySnatEntry) id() (string, error) {
	return r.SnatEntryId.Data, nil
}

func (r *mqlAlicloudVpcNatGatewayForwardEntry) id() (string, error) {
	return r.ForwardEntryId.Data, nil
}

// snatEntries lists the SNAT rules on the gateway.
func (r *mqlAlicloudVpcNatGateway) snatEntries() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(r.cacheRegion)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	collected := int32(0)
	for {
		resp, err := client.DescribeSnatTableEntries(&vpcclient.DescribeSnatTableEntriesRequest{
			RegionId:     new(r.cacheRegion),
			NatGatewayId: new(r.NatGatewayId.Data),
			PageNumber:   new(pageNumber),
			PageSize:     tea.Int32(natEntryPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.SnatTableEntries == nil {
			break
		}
		items := resp.Body.SnatTableEntries.SnatTableEntry
		for _, e := range items {
			if e == nil || e.SnatEntryId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.natGateway.snatEntry", map[string]*llx.RawData{
				"__id":               llx.StringDataPtr(e.SnatEntryId),
				"snatEntryId":        llx.StringDataPtr(e.SnatEntryId),
				"snatEntryName":      llx.StringDataPtr(e.SnatEntryName),
				"snatTableId":        llx.StringDataPtr(e.SnatTableId),
				"snatIp":             llx.StringDataPtr(e.SnatIp),
				"sourceCIDR":         llx.StringDataPtr(e.SourceCIDR),
				"sourceVSwitchId":    llx.StringDataPtr(e.SourceVSwitchId),
				"networkInterfaceId": llx.StringDataPtr(e.NetworkInterfaceId),
				"eipAffinity":        llx.StringDataPtr(e.EipAffinity),
				"status":             llx.StringDataPtr(e.Status),
			})
			if err != nil {
				return nil, err
			}
			mqlEntry := resource.(*mqlAlicloudVpcNatGatewaySnatEntry)
			mqlEntry.region = r.cacheRegion
			mqlEntry.sourceVSwitchID = tea.StringValue(e.SourceVSwitchId)
			res = append(res, mqlEntry)
		}
		collected += int32(len(items))
		if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// sourceVswitch resolves the vSwitch a SNAT rule is scoped to, or null when the
// rule is scoped by CIDR or by network interface instead.
func (r *mqlAlicloudVpcNatGatewaySnatEntry) sourceVswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.sourceVSwitchID == "" {
		r.SourceVswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	vswitch, err := resolveVpcVswitch(r.MqlRuntime, r.region, r.sourceVSwitchID)
	if err != nil || vswitch == nil {
		r.SourceVswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return vswitch, nil
}

// forwardEntries lists the DNAT rules on the gateway.
func (r *mqlAlicloudVpcNatGateway) forwardEntries() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(r.cacheRegion)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	collected := int32(0)
	for {
		resp, err := client.DescribeForwardTableEntries(&vpcclient.DescribeForwardTableEntriesRequest{
			RegionId:     new(r.cacheRegion),
			NatGatewayId: new(r.NatGatewayId.Data),
			PageNumber:   new(pageNumber),
			PageSize:     tea.Int32(natEntryPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.ForwardTableEntries == nil {
			break
		}
		items := resp.Body.ForwardTableEntries.ForwardTableEntry
		for _, e := range items {
			if e == nil || e.ForwardEntryId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.natGateway.forwardEntry", map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(e.ForwardEntryId),
				"forwardEntryId":   llx.StringDataPtr(e.ForwardEntryId),
				"forwardEntryName": llx.StringDataPtr(e.ForwardEntryName),
				"forwardTableId":   llx.StringDataPtr(e.ForwardTableId),
				"externalIp":       llx.StringDataPtr(e.ExternalIp),
				"externalPort":     llx.StringDataPtr(e.ExternalPort),
				"internalIp":       llx.StringDataPtr(e.InternalIp),
				"internalPort":     llx.StringDataPtr(e.InternalPort),
				"ipProtocol":       llx.StringDataPtr(e.IpProtocol),
				"forwardsAllPorts": llx.BoolData(natForwardsAllPorts(e.ExternalPort, e.InternalPort)),
				"status":           llx.StringDataPtr(e.Status),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
		collected += int32(len(items))
		if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}
