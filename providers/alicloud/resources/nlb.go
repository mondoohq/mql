// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	nlbclient "github.com/alibabacloud-go/nlb-20220430/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAlicloudNlb) id() (string, error) {
	return "alicloud.nlb", nil
}

func (r *mqlAlicloudNlb) loadBalancers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.NlbClient(region)
		if err != nil {
			return nil, err
		}

		var nextToken *string
		firstPage := true
		for {
			resp, err := client.ListLoadBalancers(&nlbclient.ListLoadBalancersRequest{
				RegionId:   new(region),
				MaxResults: tea.Int32(100),
				NextToken:  nextToken,
			})
			if err != nil {
				if firstPage {
					// the region may not have NLB enabled or the credential may
					// lack access there; skip it rather than failing the scan
					break
				}
				// a mid-pagination failure means the region is reachable, so the
				// error is real and must not be masked as a partial result
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}
			for _, lb := range resp.Body.LoadBalancers {
				if lb == nil || lb.LoadBalancerId == nil {
					continue
				}
				mqlLb, err := newNlbLoadBalancer(r.MqlRuntime, region, lb)
				if err != nil {
					return nil, err
				}
				if filteredOutByTags(conn, mqlLb.Tags.Data) {
					continue
				}
				res = append(res, mqlLb)
			}
			if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
				break
			}
			nextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

// mqlAlicloudNlbLoadBalancerInternal caches the identifiers for the typed
// cross-references. NLB returns zone mappings in the list, so vSwitch ids are
// cached at creation without a detail call.
type mqlAlicloudNlbLoadBalancerInternal struct {
	region                string
	loadBalancerId        string
	cacheVpcId            string
	cacheSecurityGroupIds []string
	cacheVswitchIds       []string
}

func newNlbLoadBalancer(runtime *plugin.Runtime, region string, lb *nlbclient.ListLoadBalancersResponseBodyLoadBalancers) (*mqlAlicloudNlbLoadBalancer, error) {
	lbID := tea.StringValue(lb.LoadBalancerId)

	deletionProtection := lb.DeletionProtectionConfig != nil && tea.BoolValue(lb.DeletionProtectionConfig.Enabled)
	modificationProtection := ""
	if lb.ModificationProtectionConfig != nil {
		modificationProtection = tea.StringValue(lb.ModificationProtectionConfig.Status)
	}

	vswitchIds := []string{}
	seen := map[string]struct{}{}
	for _, zm := range lb.ZoneMappings {
		if zm == nil || zm.VSwitchId == nil || *zm.VSwitchId == "" {
			continue
		}
		if _, ok := seen[*zm.VSwitchId]; ok {
			continue
		}
		seen[*zm.VSwitchId] = struct{}{}
		vswitchIds = append(vswitchIds, *zm.VSwitchId)
	}

	tags := map[string]any{}
	for _, t := range lb.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.nlb.loadBalancer", map[string]*llx.RawData{
		"__id":                         llx.StringData(region + "/" + lbID),
		"regionId":                     llx.StringData(region),
		"loadBalancerId":               llx.StringData(lbID),
		"name":                         llx.StringDataPtr(lb.LoadBalancerName),
		"status":                       llx.StringDataPtr(lb.LoadBalancerStatus),
		"type":                         llx.StringDataPtr(lb.LoadBalancerType),
		"businessStatus":               llx.StringDataPtr(lb.LoadBalancerBusinessStatus),
		"addressType":                  llx.StringDataPtr(lb.AddressType),
		"addressIpVersion":             llx.StringDataPtr(lb.AddressIpVersion),
		"ipv6AddressType":              llx.StringDataPtr(lb.Ipv6AddressType),
		"dnsName":                      llx.StringDataPtr(lb.DNSName),
		"resourceGroupId":              llx.StringDataPtr(lb.ResourceGroupId),
		"createTime":                   llx.TimeDataPtr(alicloudParseTime(lb.CreateTime)),
		"bandwidthPackageId":           llx.StringDataPtr(lb.BandwidthPackageId),
		"crossZoneEnabled":             llx.BoolDataPtr(lb.CrossZoneEnabled),
		"deletionProtectionEnabled":    llx.BoolData(deletionProtection),
		"modificationProtectionStatus": llx.StringData(modificationProtection),
		"tags":                         llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlLb := resource.(*mqlAlicloudNlbLoadBalancer)
	mqlLb.region = region
	mqlLb.loadBalancerId = lbID
	mqlLb.cacheVpcId = tea.StringValue(lb.VpcId)
	mqlLb.cacheSecurityGroupIds = strPtrsToStrings(lb.SecurityGroupIds)
	mqlLb.cacheVswitchIds = vswitchIds
	return mqlLb, nil
}

func initAlicloudNlbLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	args = scopedInitArgs(runtime, args, connection.OptionNlbID, "loadBalancerId")
	lbID, err := requiredStringArg(args, "loadBalancerId", "alicloud.nlb.loadBalancer")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.nlb.loadBalancer")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.nlb.loadBalancer\x00" + region + "/" + lbID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.NlbClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.ListLoadBalancers(&nlbclient.ListLoadBalancersRequest{
		RegionId:        new(region),
		LoadBalancerIds: []*string{new(lbID)},
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil {
		for _, lb := range resp.Body.LoadBalancers {
			if lb == nil || lb.LoadBalancerId == nil || *lb.LoadBalancerId != lbID {
				continue
			}
			res, err := newNlbLoadBalancer(runtime, region, lb)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.nlb.loadBalancer %q not found in region %q", lbID, region)
}

func (r *mqlAlicloudNlbLoadBalancer) id() (string, error) {
	return r.region + "/" + r.loadBalancerId, nil
}

func (r *mqlAlicloudNlbLoadBalancer) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcId)
}

func (r *mqlAlicloudNlbLoadBalancer) securityGroups() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheSecurityGroupIds {
		sg, err := resolveEcsSecuritygroup(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if sg != nil {
			res = append(res, sg)
		}
	}
	return res, nil
}

func (r *mqlAlicloudNlbLoadBalancer) vswitches() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVswitchIds {
		vsw, err := resolveVpcVswitch(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if vsw != nil {
			res = append(res, vsw)
		}
	}
	return res, nil
}

func (r *mqlAlicloudNlbLoadBalancer) listeners() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.NlbClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	var nextToken *string
	for {
		resp, err := client.ListListeners(&nlbclient.ListListenersRequest{
			RegionId:        new(r.region),
			LoadBalancerIds: []*string{new(r.loadBalancerId)},
			MaxResults:      tea.Int32(100),
			NextToken:       nextToken,
		})
		if err != nil {
			// the load balancer exists (it was listed), so an error listing its
			// listeners is a real failure, not a missing-service case
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, l := range resp.Body.Listeners {
			if l == nil || l.ListenerId == nil {
				continue
			}
			mqlListener, err := newNlbListener(r.MqlRuntime, r.region, l)
			if err != nil {
				return nil, err
			}
			mqlListener.parentLoadBalancer = r
			res = append(res, mqlListener)
		}
		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = resp.Body.NextToken
	}
	return res, nil
}

// mqlAlicloudNlbListenerInternal caches the region and forward server-group id
// for the typed serverGroup() reference.
type mqlAlicloudNlbListenerInternal struct {
	// parentLoadBalancer is the load balancer the listener was listed from. A
	// listener exists only as a child of its load balancer, so carrying the
	// parent from the listing context resolves the reference without an API
	// call.
	parentLoadBalancer *mqlAlicloudNlbLoadBalancer

	region             string
	listenerId         string
	cacheServerGroupId string
}

func (r *mqlAlicloudNlbListener) loadBalancer() (*mqlAlicloudNlbLoadBalancer, error) {
	if r.parentLoadBalancer == nil {
		r.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.parentLoadBalancer, nil
}

func newNlbListener(runtime *plugin.Runtime, region string, l *nlbclient.ListListenersResponseBodyListeners) (*mqlAlicloudNlbListener, error) {
	listenerID := tea.StringValue(l.ListenerId)

	tags := map[string]any{}
	for _, t := range l.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.nlb.listener", map[string]*llx.RawData{
		"__id":                 llx.StringData(region + "/" + listenerID),
		"regionId":             llx.StringData(region),
		"listenerId":           llx.StringData(listenerID),
		"loadBalancerId":       llx.StringDataPtr(l.LoadBalancerId),
		"protocol":             llx.StringDataPtr(l.ListenerProtocol),
		"port":                 llx.IntData(int64(tea.Int32Value(l.ListenerPort))),
		"status":               llx.StringDataPtr(l.ListenerStatus),
		"description":          llx.StringDataPtr(l.ListenerDescription),
		"securityPolicyId":     llx.StringDataPtr(l.SecurityPolicyId),
		"certificateIds":       llx.ArrayData(strPtrsToAny(l.CertificateIds), types.String),
		"caCertificateIds":     llx.ArrayData(strPtrsToAny(l.CaCertificateIds), types.String),
		"caEnabled":            llx.BoolDataPtr(l.CaEnabled),
		"idleTimeout":          llx.IntData(int64(tea.Int32Value(l.IdleTimeout))),
		"proxyProtocolEnabled": llx.BoolDataPtr(l.ProxyProtocolEnabled),
		"alpnEnabled":          llx.BoolDataPtr(l.AlpnEnabled),
		"alpnPolicy":           llx.StringDataPtr(l.AlpnPolicy),
		"cps":                  llx.IntData(int64(tea.Int32Value(l.Cps))),
		"tags":                 llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlListener := resource.(*mqlAlicloudNlbListener)
	mqlListener.region = region
	mqlListener.listenerId = listenerID
	mqlListener.cacheServerGroupId = tea.StringValue(l.ServerGroupId)
	return mqlListener, nil
}

func (r *mqlAlicloudNlbListener) id() (string, error) {
	return r.region + "/" + r.listenerId, nil
}

func (r *mqlAlicloudNlbListener) serverGroup() (*mqlAlicloudNlbServerGroup, error) {
	if r.cacheServerGroupId == "" {
		r.ServerGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveNlbServerGroup(r.MqlRuntime, r.region, r.cacheServerGroupId)
}

func (r *mqlAlicloudNlb) serverGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.NlbClient(region)
		if err != nil {
			return nil, err
		}
		var nextToken *string
		firstPage := true
		for {
			resp, err := client.ListServerGroups(&nlbclient.ListServerGroupsRequest{
				RegionId:   new(region),
				MaxResults: tea.Int32(100),
				NextToken:  nextToken,
			})
			if err != nil {
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}
			for _, sg := range resp.Body.ServerGroups {
				if sg == nil || sg.ServerGroupId == nil {
					continue
				}
				mqlSg, err := newNlbServerGroup(r.MqlRuntime, region, sg)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlSg)
			}
			if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
				break
			}
			nextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

// mqlAlicloudNlbServerGroupInternal caches the region and VPC id for the typed
// vpc() reference.
type mqlAlicloudNlbServerGroupInternal struct {
	region        string
	serverGroupId string
	cacheVpcId    string
}

func newNlbServerGroup(runtime *plugin.Runtime, region string, sg *nlbclient.ListServerGroupsResponseBodyServerGroups) (*mqlAlicloudNlbServerGroup, error) {
	sgID := tea.StringValue(sg.ServerGroupId)

	hcEnabled, hcType := false, ""
	var hcPort int64
	if sg.HealthCheck != nil {
		hcEnabled = tea.BoolValue(sg.HealthCheck.HealthCheckEnabled)
		hcType = tea.StringValue(sg.HealthCheck.HealthCheckType)
		hcPort = int64(tea.Int32Value(sg.HealthCheck.HealthCheckConnectPort))
	}

	tags := map[string]any{}
	for _, t := range sg.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.nlb.serverGroup", map[string]*llx.RawData{
		"__id":                    llx.StringData(region + "/" + sgID),
		"regionId":                llx.StringData(region),
		"serverGroupId":           llx.StringData(sgID),
		"name":                    llx.StringDataPtr(sg.ServerGroupName),
		"type":                    llx.StringDataPtr(sg.ServerGroupType),
		"status":                  llx.StringDataPtr(sg.ServerGroupStatus),
		"protocol":                llx.StringDataPtr(sg.Protocol),
		"scheduler":               llx.StringDataPtr(sg.Scheduler),
		"addressIpVersion":        llx.StringDataPtr(sg.AddressIPVersion),
		"serverCount":             llx.IntData(int64(tea.Int32Value(sg.ServerCount))),
		"preserveClientIpEnabled": llx.BoolDataPtr(sg.PreserveClientIpEnabled),
		"connectionDrainEnabled":  llx.BoolDataPtr(sg.ConnectionDrainEnabled),
		"healthCheckEnabled":      llx.BoolData(hcEnabled),
		"healthCheckType":         llx.StringData(hcType),
		"healthCheckConnectPort":  llx.IntData(hcPort),
		"resourceGroupId":         llx.StringDataPtr(sg.ResourceGroupId),
		"tags":                    llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlSg := resource.(*mqlAlicloudNlbServerGroup)
	mqlSg.region = region
	mqlSg.serverGroupId = sgID
	mqlSg.cacheVpcId = tea.StringValue(sg.VpcId)
	return mqlSg, nil
}

// resolveNlbServerGroup returns the typed NLB server group for an id within a
// region, or (nil, nil) when the id is empty.
func resolveNlbServerGroup(runtime *plugin.Runtime, region, sgID string) (*mqlAlicloudNlbServerGroup, error) {
	if sgID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.nlb.serverGroup", map[string]*llx.RawData{
		"serverGroupId": llx.StringData(sgID),
		"regionId":      llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudNlbServerGroup), nil
}

func initAlicloudNlbServerGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	sgID, err := requiredStringArg(args, "serverGroupId", "alicloud.nlb.serverGroup")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.nlb.serverGroup")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.nlb.serverGroup\x00" + region + "/" + sgID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.NlbClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.ListServerGroups(&nlbclient.ListServerGroupsRequest{
		RegionId:       new(region),
		ServerGroupIds: []*string{new(sgID)},
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil {
		for _, sg := range resp.Body.ServerGroups {
			if sg == nil || sg.ServerGroupId == nil || *sg.ServerGroupId != sgID {
				continue
			}
			res, err := newNlbServerGroup(runtime, region, sg)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.nlb.serverGroup %q not found in region %q", sgID, region)
}

func (r *mqlAlicloudNlbServerGroup) id() (string, error) {
	return r.region + "/" + r.serverGroupId, nil
}

func (r *mqlAlicloudNlbServerGroup) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcId)
}
