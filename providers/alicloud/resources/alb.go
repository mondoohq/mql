// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"
	"sync/atomic"

	albclient "github.com/alibabacloud-go/alb-20200616/v2/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAlicloudAlb) id() (string, error) {
	return "alicloud.alb", nil
}

func (r *mqlAlicloudAlb) loadBalancers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.AlbClient(region)
		if err != nil {
			return nil, err
		}

		var nextToken *string
		firstPage := true
		for {
			resp, err := client.ListLoadBalancers(&albclient.ListLoadBalancersRequest{
				MaxResults: tea.Int32(100),
				NextToken:  nextToken,
			})
			if err != nil {
				if firstPage {
					// the region may not have ALB enabled or the credential may
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
				mqlLb, err := newAlbLoadBalancer(r.MqlRuntime, region, lb)
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

// mqlAlicloudAlbLoadBalancerInternal caches the identifiers for the typed
// cross-references and memoizes the GetLoadBalancerAttribute detail (for zone
// vSwitch mappings).
type mqlAlicloudAlbLoadBalancerInternal struct {
	region                string
	loadBalancerId        string
	cacheVpcId            string
	cacheSecurityGroupIds []string
	cacheAccessLogProject string
	cacheAccessLogStore   string

	attrLock    sync.Mutex
	attrFetched atomic.Bool
	attr        *albclient.GetLoadBalancerAttributeResponseBody
}

// newAlbLoadBalancer builds a fully populated alicloud.alb.loadBalancer from a
// ListLoadBalancers item. Shared by the list accessor and the by-id init.
func newAlbLoadBalancer(runtime *plugin.Runtime, region string, lb *albclient.ListLoadBalancersResponseBodyLoadBalancers) (*mqlAlicloudAlbLoadBalancer, error) {
	lbID := tea.StringValue(lb.LoadBalancerId)

	deletionProtection := lb.DeletionProtectionConfig != nil && tea.BoolValue(lb.DeletionProtectionConfig.Enabled)
	modificationProtection := ""
	if lb.ModificationProtectionConfig != nil {
		modificationProtection = tea.StringValue(lb.ModificationProtectionConfig.Status)
	}
	accessLogProject, accessLogStore := "", ""
	if lb.AccessLogConfig != nil {
		accessLogProject = tea.StringValue(lb.AccessLogConfig.LogProject)
		accessLogStore = tea.StringValue(lb.AccessLogConfig.LogStore)
	}

	tags := map[string]any{}
	for _, t := range lb.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.alb.loadBalancer", map[string]*llx.RawData{
		"__id":                         llx.StringData(region + "/" + lbID),
		"regionId":                     llx.StringData(region),
		"loadBalancerId":               llx.StringData(lbID),
		"name":                         llx.StringDataPtr(lb.LoadBalancerName),
		"status":                       llx.StringDataPtr(lb.LoadBalancerStatus),
		"addressType":                  llx.StringDataPtr(lb.AddressType),
		"addressAllocatedMode":         llx.StringDataPtr(lb.AddressAllocatedMode),
		"addressIpVersion":             llx.StringDataPtr(lb.AddressIpVersion),
		"ipv6AddressType":              llx.StringDataPtr(lb.Ipv6AddressType),
		"dnsName":                      llx.StringDataPtr(lb.DNSName),
		"edition":                      llx.StringDataPtr(lb.LoadBalancerEdition),
		"businessStatus":               llx.StringDataPtr(lb.LoadBalancerBussinessStatus),
		"bandwidthPackageId":           llx.StringDataPtr(lb.BandwidthPackageId),
		"resourceGroupId":              llx.StringDataPtr(lb.ResourceGroupId),
		"createTime":                   llx.TimeDataPtr(alicloudParseTime(lb.CreateTime)),
		"deletionProtectionEnabled":    llx.BoolData(deletionProtection),
		"modificationProtectionStatus": llx.StringData(modificationProtection),
		"accessLoggingEnabled":         llx.BoolData(accessLogProject != ""),
		"tags":                         llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlLb := resource.(*mqlAlicloudAlbLoadBalancer)
	mqlLb.region = region
	mqlLb.loadBalancerId = lbID
	mqlLb.cacheVpcId = tea.StringValue(lb.VpcId)
	mqlLb.cacheSecurityGroupIds = strPtrsToStrings(lb.SecurityGroupIds)
	mqlLb.cacheAccessLogProject = accessLogProject
	mqlLb.cacheAccessLogStore = accessLogStore
	return mqlLb, nil
}

// initAlicloudAlbLoadBalancer resolves an ALB by id within a region, reusing an
// already-listed load balancer from the resource cache and otherwise fetching it
// via ListLoadBalancers filtered by id.
func initAlicloudAlbLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	args = scopedInitArgs(runtime, args, connection.OptionAlbID, "loadBalancerId")
	lbID, err := requiredStringArg(args, "loadBalancerId", "alicloud.alb.loadBalancer")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.alb.loadBalancer")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.alb.loadBalancer\x00" + region + "/" + lbID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AlbClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.ListLoadBalancers(&albclient.ListLoadBalancersRequest{
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
			res, err := newAlbLoadBalancer(runtime, region, lb)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.alb.loadBalancer %q not found in region %q", lbID, region)
}

func (r *mqlAlicloudAlbLoadBalancer) id() (string, error) {
	return r.region + "/" + r.loadBalancerId, nil
}

func (r *mqlAlicloudAlbLoadBalancer) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcId)
}

func (r *mqlAlicloudAlbLoadBalancer) securityGroups() ([]any, error) {
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

func (r *mqlAlicloudAlbLoadBalancer) accessLogProject() (*mqlAlicloudLogProject, error) {
	if r.cacheAccessLogProject == "" {
		r.AccessLogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveLogProject(r.MqlRuntime, r.region, r.cacheAccessLogProject)
}

func (r *mqlAlicloudAlbLoadBalancer) accessLogStore() (*mqlAlicloudLogLogstore, error) {
	if r.cacheAccessLogProject == "" || r.cacheAccessLogStore == "" {
		r.AccessLogStore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveLogStore(r.MqlRuntime, r.region, r.cacheAccessLogProject, r.cacheAccessLogStore)
}

// attribute lazily fetches GetLoadBalancerAttribute for the zone vSwitch
// mappings. A transient error is not cached and is returned.
func (r *mqlAlicloudAlbLoadBalancer) attribute() (*albclient.GetLoadBalancerAttributeResponseBody, error) {
	if r.attrFetched.Load() {
		return r.attr, nil
	}
	r.attrLock.Lock()
	defer r.attrLock.Unlock()
	if r.attrFetched.Load() {
		return r.attr, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AlbClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetLoadBalancerAttribute(&albclient.GetLoadBalancerAttributeRequest{
		LoadBalancerId: new(r.loadBalancerId),
	})
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.attr = resp.Body
	}
	r.attrFetched.Store(true)
	return r.attr, nil
}

func (r *mqlAlicloudAlbLoadBalancer) vswitches() ([]any, error) {
	attr, err := r.attribute()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if attr == nil {
		return res, nil
	}
	seen := map[string]struct{}{}
	for _, zm := range attr.ZoneMappings {
		if zm == nil || zm.VSwitchId == nil || *zm.VSwitchId == "" {
			continue
		}
		if _, ok := seen[*zm.VSwitchId]; ok {
			continue
		}
		seen[*zm.VSwitchId] = struct{}{}
		vsw, err := resolveVpcVswitch(r.MqlRuntime, r.region, *zm.VSwitchId)
		if err != nil {
			return nil, err
		}
		if vsw != nil {
			res = append(res, vsw)
		}
	}
	return res, nil
}

func (r *mqlAlicloudAlbLoadBalancer) listeners() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AlbClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	var nextToken *string
	for {
		resp, err := client.ListListeners(&albclient.ListListenersRequest{
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
			mqlListener, err := newAlbListener(r.MqlRuntime, r.region, l)
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

// mqlAlicloudAlbListenerInternal caches the forward server-group ids and
// memoizes the GetListenerAttribute detail (for certificates and mTLS state).
type mqlAlicloudAlbListenerInternal struct {
	// parentLoadBalancer is the load balancer the listener was listed from. A
	// listener exists only as a child of its load balancer, so carrying the
	// parent from the listing context resolves the reference without an API
	// call.
	parentLoadBalancer *mqlAlicloudAlbLoadBalancer

	region              string
	listenerId          string
	cacheServerGroupIds []string

	attrLock    sync.Mutex
	attrFetched atomic.Bool
	attr        *albclient.GetListenerAttributeResponseBody
}

func newAlbListener(runtime *plugin.Runtime, region string, l *albclient.ListListenersResponseBodyListeners) (*mqlAlicloudAlbListener, error) {
	listenerID := tea.StringValue(l.ListenerId)

	sgIds := []string{}
	for _, a := range l.DefaultActions {
		if a == nil || a.ForwardGroupConfig == nil {
			continue
		}
		for _, t := range a.ForwardGroupConfig.ServerGroupTuples {
			if t != nil && t.ServerGroupId != nil && *t.ServerGroupId != "" {
				sgIds = append(sgIds, *t.ServerGroupId)
			}
		}
	}

	tags := map[string]any{}
	for _, t := range l.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.alb.listener", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + listenerID),
		"regionId":         llx.StringData(region),
		"listenerId":       llx.StringData(listenerID),
		"loadBalancerId":   llx.StringDataPtr(l.LoadBalancerId),
		"protocol":         llx.StringDataPtr(l.ListenerProtocol),
		"port":             llx.IntData(int64(tea.Int32Value(l.ListenerPort))),
		"status":           llx.StringDataPtr(l.ListenerStatus),
		"description":      llx.StringDataPtr(l.ListenerDescription),
		"securityPolicyId": llx.StringDataPtr(l.SecurityPolicyId),
		"http2Enabled":     llx.BoolDataPtr(l.Http2Enabled),
		"gzipEnabled":      llx.BoolDataPtr(l.GzipEnabled),
		"idleTimeout":      llx.IntData(int64(tea.Int32Value(l.IdleTimeout))),
		"requestTimeout":   llx.IntData(int64(tea.Int32Value(l.RequestTimeout))),
		"tags":             llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlListener := resource.(*mqlAlicloudAlbListener)
	mqlListener.region = region
	mqlListener.listenerId = listenerID
	mqlListener.cacheServerGroupIds = sgIds
	return mqlListener, nil
}

func (r *mqlAlicloudAlbListener) loadBalancer() (*mqlAlicloudAlbLoadBalancer, error) {
	if r.parentLoadBalancer == nil {
		r.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.parentLoadBalancer, nil
}

func (r *mqlAlicloudAlbListener) id() (string, error) {
	return r.region + "/" + r.listenerId, nil
}

// listenerAttribute lazily fetches GetListenerAttribute (certificates, mTLS). A
// transient error is not cached and is returned.
func (r *mqlAlicloudAlbListener) listenerAttribute() (*albclient.GetListenerAttributeResponseBody, error) {
	if r.attrFetched.Load() {
		return r.attr, nil
	}
	r.attrLock.Lock()
	defer r.attrLock.Unlock()
	if r.attrFetched.Load() {
		return r.attr, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AlbClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetListenerAttribute(&albclient.GetListenerAttributeRequest{
		ListenerId: new(r.listenerId),
	})
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.attr = resp.Body
	}
	r.attrFetched.Store(true)
	return r.attr, nil
}

func (r *mqlAlicloudAlbListener) certificateIds() ([]any, error) {
	attr, err := r.listenerAttribute()
	if err != nil || attr == nil {
		return []any{}, err
	}
	res := []any{}
	for _, c := range attr.Certificates {
		if c == nil || c.CertificateId == nil {
			continue
		}
		res = append(res, tea.StringValue(c.CertificateId))
	}
	return res, nil
}

func (r *mqlAlicloudAlbListener) mutualTlsEnabled() (bool, error) {
	attr, err := r.listenerAttribute()
	if err != nil || attr == nil {
		return false, err
	}
	return tea.BoolValue(attr.CaEnabled), nil
}

func (r *mqlAlicloudAlbListener) serverGroups() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheServerGroupIds {
		sg, err := resolveAlbServerGroup(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if sg != nil {
			res = append(res, sg)
		}
	}
	return res, nil
}

func (r *mqlAlicloudAlb) serverGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.AlbClient(region)
		if err != nil {
			return nil, err
		}
		var nextToken *string
		firstPage := true
		for {
			resp, err := client.ListServerGroups(&albclient.ListServerGroupsRequest{
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
				mqlSg, err := newAlbServerGroup(r.MqlRuntime, region, sg)
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

// mqlAlicloudAlbServerGroupInternal caches the region and VPC id for the typed
// vpc() reference.
type mqlAlicloudAlbServerGroupInternal struct {
	region        string
	serverGroupId string
	cacheVpcId    string
}

func newAlbServerGroup(runtime *plugin.Runtime, region string, sg *albclient.ListServerGroupsResponseBodyServerGroups) (*mqlAlicloudAlbServerGroup, error) {
	sgID := tea.StringValue(sg.ServerGroupId)

	hcEnabled, hcProtocol, hcPath := false, "", ""
	if sg.HealthCheckConfig != nil {
		hcEnabled = tea.BoolValue(sg.HealthCheckConfig.HealthCheckEnabled)
		hcProtocol = tea.StringValue(sg.HealthCheckConfig.HealthCheckProtocol)
		hcPath = tea.StringValue(sg.HealthCheckConfig.HealthCheckPath)
	}
	stickyEnabled, stickyType := false, ""
	if sg.StickySessionConfig != nil {
		stickyEnabled = tea.BoolValue(sg.StickySessionConfig.StickySessionEnabled)
		stickyType = tea.StringValue(sg.StickySessionConfig.StickySessionType)
	}

	tags := map[string]any{}
	for _, t := range sg.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	resource, err := CreateResource(runtime, "alicloud.alb.serverGroup", map[string]*llx.RawData{
		"__id":                 llx.StringData(region + "/" + sgID),
		"regionId":             llx.StringData(region),
		"serverGroupId":        llx.StringData(sgID),
		"name":                 llx.StringDataPtr(sg.ServerGroupName),
		"type":                 llx.StringDataPtr(sg.ServerGroupType),
		"status":               llx.StringDataPtr(sg.ServerGroupStatus),
		"protocol":             llx.StringDataPtr(sg.Protocol),
		"scheduler":            llx.StringDataPtr(sg.Scheduler),
		"serverCount":          llx.IntData(int64(tea.Int32Value(sg.ServerCount))),
		"resourceGroupId":      llx.StringDataPtr(sg.ResourceGroupId),
		"createTime":           llx.TimeDataPtr(alicloudParseTime(sg.CreateTime)),
		"crossZoneEnabled":     llx.BoolDataPtr(sg.CrossZoneEnabled),
		"healthCheckEnabled":   llx.BoolData(hcEnabled),
		"healthCheckProtocol":  llx.StringData(hcProtocol),
		"healthCheckPath":      llx.StringData(hcPath),
		"stickySessionEnabled": llx.BoolData(stickyEnabled),
		"stickySessionType":    llx.StringData(stickyType),
		"tags":                 llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlSg := resource.(*mqlAlicloudAlbServerGroup)
	mqlSg.region = region
	mqlSg.serverGroupId = sgID
	mqlSg.cacheVpcId = tea.StringValue(sg.VpcId)
	return mqlSg, nil
}

// resolveAlbServerGroup returns the typed ALB server group for an id within a
// region, or (nil, nil) when the id is empty.
func resolveAlbServerGroup(runtime *plugin.Runtime, region, sgID string) (*mqlAlicloudAlbServerGroup, error) {
	if sgID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.alb.serverGroup", map[string]*llx.RawData{
		"serverGroupId": llx.StringData(sgID),
		"regionId":      llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudAlbServerGroup), nil
}

func initAlicloudAlbServerGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	sgID, err := requiredStringArg(args, "serverGroupId", "alicloud.alb.serverGroup")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.alb.serverGroup")
	if err != nil {
		return nil, nil, err
	}
	if x, ok := runtime.Resources.Get("alicloud.alb.serverGroup\x00" + region + "/" + sgID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AlbClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.ListServerGroups(&albclient.ListServerGroupsRequest{
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
			res, err := newAlbServerGroup(runtime, region, sg)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.alb.serverGroup %q not found in region %q", sgID, region)
}

func (r *mqlAlicloudAlbServerGroup) id() (string, error) {
	return r.region + "/" + r.serverGroupId, nil
}

func (r *mqlAlicloudAlbServerGroup) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcId)
}
