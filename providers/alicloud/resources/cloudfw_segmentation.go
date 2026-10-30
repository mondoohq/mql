// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	cloudfwclient "github.com/alibabacloud-go/cloudfw-20171207/v11/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// cloudfwPolicyPageSize is the page size used for the paged Cloud Firewall
// policy endpoints. They cap the page server-side, so the walks below terminate
// on the accumulated count against TotalCount rather than on a short page.
const cloudfwPolicyPageSize = 50

// cloudfwSwitchEnabled reports whether an int32 Cloud Firewall switch is on.
// The API encodes these as 1 for enabled and 0 for disabled; an absent value
// reads as off, so an unread switch never reports protection nobody confirmed.
func cloudfwSwitchEnabled(v *int32) bool {
	return tea.Int32Value(v) == 1
}

// cloudfwPolicyEnabled reports whether a control policy is enforced. Cloud
// Firewall returns the Release member as the string "true" or "false" rather
// than as a boolean.
func cloudfwPolicyEnabled(release *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(release)), "true")
}

// cloudfwVpcFirewallEnabled reports whether a VPC firewall is switched on. Only
// opened counts: closed and notconfigured both leave the guarded VPC pair
// carrying traffic with nothing inspecting it.
func cloudfwVpcFirewallEnabled(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "opened")
}

// cloudfwNatFirewallEnabled reports whether a NAT firewall is inspecting
// traffic. Only normal counts: configuring, opening and closing are
// transitional, and abnormal means the firewall exists but is not working, which
// leaves egress uninspected just as surely as closed does.
func cloudfwNatFirewallEnabled(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "normal")
}

// cloudfwCrossAccount reports whether a VPC firewall's peer belongs to a
// different Alibaba Cloud account than its local end. An owner id that is
// missing on either side is not evidence of a foreign peer, so the pair reads as
// same-account.
func cloudfwCrossAccount(localOwner, peerOwner *int64) bool {
	local := tea.Int64Value(localOwner)
	peer := tea.Int64Value(peerOwner)
	if local == 0 || peer == 0 {
		return false
	}
	return local != peer
}

// cloudfwOwnerString renders an account id for display, returning an empty
// string rather than "0" when the API did not report one.
func cloudfwOwnerString(owner *int64) string {
	v := tea.Int64Value(owner)
	if v == 0 {
		return ""
	}
	return strconv.FormatInt(v, 10)
}

// cloudfwPolicyMore reports whether a paged Cloud Firewall policy listing has
// further pages. TotalCount arrives as a string, and a response that omits it
// (or renders it unparseable) must stop the walk rather than loop forever.
func cloudfwPolicyMore(collected int, totalCount *string) bool {
	total, err := strconv.Atoi(strings.TrimSpace(tea.StringValue(totalCount)))
	if err != nil {
		return false
	}
	return collected < total
}

// mqlAlicloudCloudFirewallVpcFirewallInternal caches the center region the
// firewall was listed from, which its policy lookup needs, and the local VPC
// identity used by the typed reference.
type mqlAlicloudCloudFirewallVpcFirewallInternal struct {
	centerRegion string
	localVpcID   string
}

// mqlAlicloudCloudFirewallNatFirewallInternal caches the center region the
// firewall was listed from and the ids its typed references resolve.
type mqlAlicloudCloudFirewallNatFirewallInternal struct {
	centerRegion string
	vpcID        string
	natGatewayID string
}

func (r *mqlAlicloudCloudFirewallVpcFirewall) id() (string, error) {
	return r.VpcFirewallId.Data, nil
}

func (r *mqlAlicloudCloudFirewallVpcControlPolicy) id() (string, error) {
	return r.AclUuid.Data, nil
}

func (r *mqlAlicloudCloudFirewallNatFirewall) id() (string, error) {
	return r.ProxyId.Data, nil
}

func (r *mqlAlicloudCloudFirewallNatControlPolicy) id() (string, error) {
	return r.AclUuid.Data, nil
}

// vpcFirewalls enumerates the account's VPC firewalls. Cloud Firewall answers at
// one center for the whole account, which buyVersion has already probed, so the
// listing is a single paged walk rather than a per-region fan-out.
func (r *mqlAlicloudCloudFirewall) vpcFirewalls() ([]any, error) {
	region, v, err := r.buyVersion()
	if err != nil {
		return nil, err
	}
	if region == "" || v == nil {
		// Cloud Firewall is not provisioned for this account
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudfwClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	currentPage := 1
	collected := 0
	for {
		resp, err := client.DescribeVpcFirewallList(&cloudfwclient.DescribeVpcFirewallListRequest{
			CurrentPage: new(strconv.Itoa(currentPage)),
			PageSize:    new(strconv.Itoa(cloudfwPolicyPageSize)),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.VpcFirewalls
		for _, fw := range items {
			if fw == nil || fw.VpcFirewallId == nil {
				continue
			}
			mqlFirewall, err := newCloudfwVpcFirewall(r.MqlRuntime, region, fw)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFirewall)
		}
		collected += len(items)
		total := int(tea.Int32Value(resp.Body.TotalCount))
		if len(items) == 0 || collected >= total {
			break
		}
		currentPage++
	}
	return res, nil
}

// newCloudfwVpcFirewall maps one DescribeVpcFirewallList item to a resource.
func newCloudfwVpcFirewall(runtime *plugin.Runtime, centerRegion string, fw *cloudfwclient.DescribeVpcFirewallListResponseBodyVpcFirewalls) (*mqlAlicloudCloudFirewallVpcFirewall, error) {
	var (
		strictMode                                        *int32
		ipsMode, ipsBasicRules, ipsAllPatch, ipsRuleClass *int32
		localVpcID, localVpcName, localRegion             string
		peerVpcID, peerVpcName, peerRegion                string
		localOwner, peerOwner                             *int64
	)
	if fw.AclConfig != nil {
		strictMode = fw.AclConfig.StrictMode
	}
	if ips := fw.IpsConfig; ips != nil {
		ipsMode = ips.RunMode
		ipsBasicRules = ips.BasicRules
		ipsAllPatch = ips.EnableAllPatch
		ipsRuleClass = ips.RuleClass
	}
	if lv := fw.LocalVpc; lv != nil {
		localVpcID = tea.StringValue(lv.VpcId)
		localVpcName = tea.StringValue(lv.VpcName)
		localRegion = tea.StringValue(lv.RegionNo)
		localOwner = lv.OwnerId
	}
	if pv := fw.PeerVpc; pv != nil {
		peerVpcID = tea.StringValue(pv.VpcId)
		peerVpcName = tea.StringValue(pv.VpcName)
		peerRegion = tea.StringValue(pv.RegionNo)
		peerOwner = pv.OwnerId
	}
	resource, err := CreateResource(runtime, "alicloud.cloudFirewall.vpcFirewall", map[string]*llx.RawData{
		"__id":                   llx.StringDataPtr(fw.VpcFirewallId),
		"vpcFirewallId":          llx.StringDataPtr(fw.VpcFirewallId),
		"vpcFirewallName":        llx.StringDataPtr(fw.VpcFirewallName),
		"connectType":            llx.StringDataPtr(fw.ConnectType),
		"connectSubType":         llx.StringDataPtr(fw.ConnectSubType),
		"bandwidth":              llx.IntData(int64(tea.Int32Value(fw.Bandwidth))),
		"firewallSwitchStatus":   llx.StringDataPtr(fw.FirewallSwitchStatus),
		"enabled":                llx.BoolData(cloudfwVpcFirewallEnabled(fw.FirewallSwitchStatus)),
		"regionStatus":           llx.StringDataPtr(fw.RegionStatus),
		"strictMode":             llx.BoolData(cloudfwSwitchEnabled(strictMode)),
		"ipsBlocking":            llx.BoolData(cloudfwSwitchEnabled(ipsMode)),
		"ipsMode":                llx.IntData(int64(tea.Int32Value(ipsMode))),
		"ipsBasicRulesEnabled":   llx.BoolData(cloudfwSwitchEnabled(ipsBasicRules)),
		"ipsVirtualPatchEnabled": llx.BoolData(cloudfwSwitchEnabled(ipsAllPatch)),
		"ipsRuleClass":           llx.IntData(int64(tea.Int32Value(ipsRuleClass))),
		"localRegionId":          llx.StringData(localRegion),
		"localVpcName":           llx.StringData(localVpcName),
		"peerRegionId":           llx.StringData(peerRegion),
		"peerVpcId":              llx.StringData(peerVpcID),
		"peerVpcName":            llx.StringData(peerVpcName),
		"peerVpcOwnerId":         llx.StringData(cloudfwOwnerString(peerOwner)),
		"crossAccount":           llx.BoolData(cloudfwCrossAccount(localOwner, peerOwner)),
	})
	if err != nil {
		return nil, err
	}
	mqlFirewall := resource.(*mqlAlicloudCloudFirewallVpcFirewall)
	mqlFirewall.centerRegion = centerRegion
	mqlFirewall.localVpcID = localVpcID
	return mqlFirewall, nil
}

// localVpc resolves the local end of the guarded pair. The VPC may lie outside
// the scanned regions, in which case the reference is null rather than an error:
// one unreachable VPC must not fail a query over every firewall.
func (r *mqlAlicloudCloudFirewallVpcFirewall) localVpc() (*mqlAlicloudVpcNetwork, error) {
	return cloudfwResolveVpc(r.MqlRuntime, r.LocalRegionId.Data, r.localVpcID, &r.LocalVpc)
}

// peerVpc resolves the far end of the guarded pair. A peer owned by another
// account cannot be read with these credentials, so the reference is null there;
// peerVpcId and peerVpcOwnerId remain as the record of what the pair reaches.
func (r *mqlAlicloudCloudFirewallVpcFirewall) peerVpc() (*mqlAlicloudVpcNetwork, error) {
	return cloudfwResolveVpc(r.MqlRuntime, r.PeerRegionId.Data, r.PeerVpcId.Data, &r.PeerVpc)
}

// cloudfwResolveVpc resolves a VPC reference, degrading to null on an empty id
// or an unreadable network.
func cloudfwResolveVpc(runtime *plugin.Runtime, region, vpcID string, field *plugin.TValue[*mqlAlicloudVpcNetwork]) (*mqlAlicloudVpcNetwork, error) {
	if region == "" || vpcID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	network, err := resolveVpcNetwork(runtime, region, vpcID)
	if err != nil || network == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return network, nil
}

// controlPolicies lists the east-west rules enforced by this VPC firewall.
func (r *mqlAlicloudCloudFirewallVpcFirewall) controlPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudfwClient(r.centerRegion)
	if err != nil {
		return nil, err
	}

	res := []any{}
	currentPage := 1
	collected := 0
	for {
		resp, err := client.DescribeVpcFirewallControlPolicy(&cloudfwclient.DescribeVpcFirewallControlPolicyRequest{
			VpcFirewallId: new(r.VpcFirewallId.Data),
			CurrentPage:   new(strconv.Itoa(currentPage)),
			PageSize:      new(strconv.Itoa(cloudfwPolicyPageSize)),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Policys
		for _, p := range items {
			if p == nil || p.AclUuid == nil {
				continue
			}
			// the listing is scoped to one firewall, so the UUID is only known to
			// be unique within it and is qualified before it becomes a key
			resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudFirewall.vpcControlPolicy", map[string]*llx.RawData{
				"__id":                  llx.StringData(r.VpcFirewallId.Data + "/" + tea.StringValue(p.AclUuid)),
				"aclUuid":               llx.StringDataPtr(p.AclUuid),
				"vpcFirewallId":         llx.StringData(r.VpcFirewallId.Data),
				"action":                llx.StringDataPtr(p.AclAction),
				"source":                llx.StringDataPtr(p.Source),
				"sourceType":            llx.StringDataPtr(p.SourceType),
				"sourceGroupCidrs":      llx.ArrayData(strPtrsToAny(p.SourceGroupCidrs), types.String),
				"destination":           llx.StringDataPtr(p.Destination),
				"destinationType":       llx.StringDataPtr(p.DestinationType),
				"destinationGroupCidrs": llx.ArrayData(strPtrsToAny(p.DestinationGroupCidrs), types.String),
				"destPort":              llx.StringDataPtr(p.DestPort),
				"destPortType":          llx.StringDataPtr(p.DestPortType),
				"destPortGroupPorts":    llx.ArrayData(strPtrsToAny(p.DestPortGroupPorts), types.String),
				"proto":                 llx.StringDataPtr(p.Proto),
				"applicationNames":      llx.ArrayData(strPtrsToAny(p.ApplicationNameList), types.String),
				"description":           llx.StringDataPtr(p.Description),
				"enabled":               llx.BoolData(cloudfwPolicyEnabled(p.Release)),
				"order":                 llx.IntData(int64(tea.Int32Value(p.Order))),
				"hitTimes":              llx.IntData(tea.Int64Value(p.HitTimes)),
				"lastHitTime":           llx.TimeDataPtr(epochSeconds(p.HitLastTime)),
				"createTime":            llx.TimeDataPtr(epochSeconds(p.CreateTime)),
				"updateTime":            llx.TimeDataPtr(epochSeconds(p.ModifyTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
		collected += len(items)
		if len(items) == 0 || !cloudfwPolicyMore(collected, resp.Body.TotalCount) {
			break
		}
		currentPage++
	}
	return res, nil
}

// natFirewalls enumerates the account's NAT firewalls.
func (r *mqlAlicloudCloudFirewall) natFirewalls() ([]any, error) {
	region, v, err := r.buyVersion()
	if err != nil {
		return nil, err
	}
	if region == "" || v == nil {
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudfwClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNo := int64(1)
	collected := 0
	for {
		resp, err := client.DescribeNatFirewallList(&cloudfwclient.DescribeNatFirewallListRequest{
			PageNo:   new(pageNo),
			PageSize: tea.Int64(cloudfwPolicyPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.NatFirewallList
		for _, fw := range items {
			if fw == nil || fw.ProxyId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudFirewall.natFirewall", map[string]*llx.RawData{
				"__id":           llx.StringDataPtr(fw.ProxyId),
				"proxyId":        llx.StringDataPtr(fw.ProxyId),
				"proxyName":      llx.StringDataPtr(fw.ProxyName),
				"regionId":       llx.StringDataPtr(fw.RegionId),
				"proxyStatus":    llx.StringDataPtr(fw.ProxyStatus),
				"enabled":        llx.BoolData(cloudfwNatFirewallEnabled(fw.ProxyStatus)),
				"strictMode":     llx.BoolData(cloudfwSwitchEnabled(fw.StrictMode)),
				"errorDetail":    llx.StringDataPtr(fw.ErrorDetail),
				"vpcName":        llx.StringDataPtr(fw.VpcName),
				"natGatewayName": llx.StringDataPtr(fw.NatGatewayName),
			})
			if err != nil {
				return nil, err
			}
			mqlFirewall := resource.(*mqlAlicloudCloudFirewallNatFirewall)
			mqlFirewall.centerRegion = region
			mqlFirewall.vpcID = tea.StringValue(fw.VpcId)
			mqlFirewall.natGatewayID = tea.StringValue(fw.NatGatewayId)
			res = append(res, mqlFirewall)
		}
		collected += len(items)
		total := int(tea.Int32Value(resp.Body.TotalCount))
		if len(items) == 0 || collected >= total {
			break
		}
		pageNo++
	}
	return res, nil
}

// vpc resolves the VPC the guarded NAT gateway belongs to.
func (r *mqlAlicloudCloudFirewallNatFirewall) vpc() (*mqlAlicloudVpcNetwork, error) {
	return cloudfwResolveVpc(r.MqlRuntime, r.RegionId.Data, r.vpcID, &r.Vpc)
}

// natGateway resolves the gateway this firewall guards, or null when the
// gateway lies outside the scanned regions or has since been deleted.
func (r *mqlAlicloudCloudFirewallNatFirewall) natGateway() (*mqlAlicloudVpcNatGateway, error) {
	if r.RegionId.Data == "" || r.natGatewayID == "" {
		r.NatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	gateway, err := resolveVpcNatGateway(r.MqlRuntime, r.RegionId.Data, r.natGatewayID)
	if err != nil || gateway == nil {
		r.NatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gateway, nil
}

// controlPolicies lists the egress and ingress rules enforced on the guarded NAT
// gateway. The endpoint is keyed on a direction, so both are walked and the
// results concatenated, the same shape the internet-boundary listing uses.
func (r *mqlAlicloudCloudFirewallNatFirewall) controlPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudfwClient(r.centerRegion)
	if err != nil {
		return nil, err
	}
	if r.natGatewayID == "" {
		return []any{}, nil
	}

	res := []any{}
	for _, direction := range []string{"in", "out"} {
		currentPage := 1
		collected := 0
		for {
			resp, err := client.DescribeNatFirewallControlPolicy(&cloudfwclient.DescribeNatFirewallControlPolicyRequest{
				NatGatewayId: new(r.natGatewayID),
				Direction:    new(direction),
				CurrentPage:  new(strconv.Itoa(currentPage)),
				PageSize:     new(strconv.Itoa(cloudfwPolicyPageSize)),
			})
			if err != nil {
				return nil, err
			}
			if resp == nil || resp.Body == nil {
				break
			}
			items := resp.Body.Policys
			for _, p := range items {
				if p == nil || p.AclUuid == nil {
					continue
				}
				// the listing is scoped to one gateway and one direction, so the
				// UUID is qualified with both rather than trusted to be global
				resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudFirewall.natControlPolicy", map[string]*llx.RawData{
					"__id":                  llx.StringData(r.natGatewayID + "/" + direction + "/" + tea.StringValue(p.AclUuid)),
					"aclUuid":               llx.StringDataPtr(p.AclUuid),
					"natGatewayId":          llx.StringData(r.natGatewayID),
					"direction":             llx.StringData(direction),
					"action":                llx.StringDataPtr(p.AclAction),
					"source":                llx.StringDataPtr(p.Source),
					"sourceType":            llx.StringDataPtr(p.SourceType),
					"sourceGroupCidrs":      llx.ArrayData(strPtrsToAny(p.SourceGroupCidrs), types.String),
					"destination":           llx.StringDataPtr(p.Destination),
					"destinationType":       llx.StringDataPtr(p.DestinationType),
					"destinationGroupCidrs": llx.ArrayData(strPtrsToAny(p.DestinationGroupCidrs), types.String),
					"destPort":              llx.StringDataPtr(p.DestPort),
					"destPortType":          llx.StringDataPtr(p.DestPortType),
					"destPortGroupPorts":    llx.ArrayData(strPtrsToAny(p.DestPortGroupPorts), types.String),
					"proto":                 llx.StringDataPtr(p.Proto),
					"applicationNames":      llx.ArrayData(strPtrsToAny(p.ApplicationNameList), types.String),
					"description":           llx.StringDataPtr(p.Description),
					"enabled":               llx.BoolData(cloudfwPolicyEnabled(p.Release)),
					"order":                 llx.IntData(int64(tea.Int32Value(p.Order))),
					"hitTimes":              llx.IntData(tea.Int64Value(p.HitTimes)),
					"lastHitTime":           llx.TimeDataPtr(epochSeconds(p.HitLastTime)),
					"createTime":            llx.TimeDataPtr(epochSeconds(p.CreateTime)),
					"updateTime":            llx.TimeDataPtr(epochSeconds(p.ModifyTime)),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			collected += len(items)
			if len(items) == 0 || !cloudfwPolicyMore(collected, resp.Body.TotalCount) {
				break
			}
			currentPage++
		}
	}
	return res, nil
}
