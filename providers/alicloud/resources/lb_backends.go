// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	albclient "github.com/alibabacloud-go/alb-20200616/v2/client"
	nlbclient "github.com/alibabacloud-go/nlb-20220430/v4/client"
	slbclient "github.com/alibabacloud-go/slb-20140515/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// resolveBackendEcsInstance returns the ECS instance sitting behind a load
// balancer backend, or nil when the backend is not an instance.
//
// This resolves one instance at a time rather than scanning a shared list, and
// that is the right trade here: the only shared list available is every ECS
// instance in every region, which for an account with thousands of instances
// costs far more than the handful of lookups a backend set needs.
// initAlicloudEcsInstance checks the resource cache before calling out, so an
// instance behind several load balancers is fetched once.
func resolveBackendEcsInstance(runtime *plugin.Runtime, region, serverID string, field *plugin.TValue[*mqlAlicloudEcsInstance]) (*mqlAlicloudEcsInstance, error) {
	if region == "" || serverID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.ecs.instance", map[string]*llx.RawData{
		"instanceId": llx.StringData(serverID),
		"regionId":   llx.StringData(region),
	})
	if err != nil {
		// A backend can name an instance that has since been released, and the
		// load balancer keeps forwarding to it either way. Nulling the reference
		// keeps the backend visible; failing here would hide the whole set.
		log.Debug().Err(err).Str("instanceId", serverID).Str("region", region).
			Msg("alicloud> unable to resolve the load balancer backend instance")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAlicloudEcsInstance), nil
}

// backendIsEcs reports whether a backend's type names an ECS instance. The three
// load balancer families spell it differently (ALB and NLB use "Ecs", CLB uses
// "ecs"), so the comparison is case-insensitive.
func backendIsEcs(serverType string) bool {
	return strings.EqualFold(strings.TrimSpace(serverType), "ecs")
}

// -----------------------------------------------------------------------------
// ALB
// -----------------------------------------------------------------------------

func (r *mqlAlicloudAlbServerGroup) servers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.AlbClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	var nextToken *string
	for {
		resp, err := client.ListServerGroupServers(&albclient.ListServerGroupServersRequest{
			ServerGroupId: new(r.serverGroupId),
			MaxResults:    tea.Int32(100),
			NextToken:     nextToken,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, s := range resp.Body.Servers {
			if s == nil || s.ServerId == nil {
				continue
			}
			serverID := tea.StringValue(s.ServerId)
			port := int64(tea.Int32Value(s.Port))
			resource, err := CreateResource(r.MqlRuntime, "alicloud.alb.serverGroup.server", map[string]*llx.RawData{
				// a server can be attached to one group on several ports, so the
				// port is part of the key
				"__id":            llx.StringData(backendServerKey(r.region, r.serverGroupId, serverID, port)),
				"serverId":        llx.StringData(serverID),
				"serverType":      llx.StringDataPtr(s.ServerType),
				"serverIp":        llx.StringDataPtr(s.ServerIp),
				"port":            llx.IntData(port),
				"weight":          llx.IntData(int64(tea.Int32Value(s.Weight))),
				"status":          llx.StringDataPtr(s.Status),
				"remoteIpEnabled": llx.BoolData(tea.BoolValue(s.RemoteIpEnabled)),
				"description":     llx.StringDataPtr(s.Description),
			})
			if err != nil {
				return nil, err
			}
			mqlServer := resource.(*mqlAlicloudAlbServerGroupServer)
			mqlServer.region = r.region
			res = append(res, mqlServer)
		}

		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = resp.Body.NextToken
	}
	return res, nil
}

// backendServerKey builds the cache key for a load balancer backend, and is
// shared by all three families. The owner is whatever holds the backend: a
// server group for ALB and NLB, and either the load balancer or a vServer group
// for CLB. Both the owner and the port are part of the key, because a server can
// sit under one owner on several ports and can back several owners at once.
func backendServerKey(region, ownerID, serverID string, port int64) string {
	return region + "/" + ownerID + "/" + serverID + "/" + strconv.FormatInt(port, 10)
}

// mqlAlicloudAlbServerGroupServerInternal caches the region the backend was
// listed in, which its instance reference needs.
type mqlAlicloudAlbServerGroupServerInternal struct {
	region string
}

func (r *mqlAlicloudAlbServerGroupServer) ecsInstance() (*mqlAlicloudEcsInstance, error) {
	if !backendIsEcs(r.ServerType.Data) {
		r.EcsInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveBackendEcsInstance(r.MqlRuntime, r.region, r.ServerId.Data, &r.EcsInstance)
}

// -----------------------------------------------------------------------------
// NLB
// -----------------------------------------------------------------------------

func (r *mqlAlicloudNlbServerGroup) servers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.NlbClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	var nextToken *string
	for {
		resp, err := client.ListServerGroupServers(&nlbclient.ListServerGroupServersRequest{
			ServerGroupId: new(r.serverGroupId),
			MaxResults:    tea.Int32(100),
			NextToken:     nextToken,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, s := range resp.Body.Servers {
			if s == nil || s.ServerId == nil {
				continue
			}
			serverID := tea.StringValue(s.ServerId)
			port := int64(tea.Int32Value(s.Port))
			resource, err := CreateResource(r.MqlRuntime, "alicloud.nlb.serverGroup.server", map[string]*llx.RawData{
				"__id":        llx.StringData(backendServerKey(r.region, r.serverGroupId, serverID, port)),
				"serverId":    llx.StringData(serverID),
				"serverType":  llx.StringDataPtr(s.ServerType),
				"serverIp":    llx.StringDataPtr(s.ServerIp),
				"port":        llx.IntData(port),
				"weight":      llx.IntData(int64(tea.Int32Value(s.Weight))),
				"status":      llx.StringDataPtr(s.Status),
				"zoneId":      llx.StringDataPtr(s.ZoneId),
				"description": llx.StringDataPtr(s.Description),
			})
			if err != nil {
				return nil, err
			}
			mqlServer := resource.(*mqlAlicloudNlbServerGroupServer)
			mqlServer.region = r.region
			res = append(res, mqlServer)
		}

		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = resp.Body.NextToken
	}
	return res, nil
}

// mqlAlicloudNlbServerGroupServerInternal caches the region the backend was
// listed in, which its instance reference needs.
type mqlAlicloudNlbServerGroupServerInternal struct {
	region string
}

func (r *mqlAlicloudNlbServerGroupServer) ecsInstance() (*mqlAlicloudEcsInstance, error) {
	if !backendIsEcs(r.ServerType.Data) {
		r.EcsInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveBackendEcsInstance(r.MqlRuntime, r.region, r.ServerId.Data, &r.EcsInstance)
}

// -----------------------------------------------------------------------------
// CLB (slb)
// -----------------------------------------------------------------------------

// newSlbBackendServer builds one alicloud.slb.backendServer. The owner is either
// the load balancer, for a directly attached backend, or a vServer group,
// because the same instance can sit in both places at once.
func newSlbBackendServer(runtime *plugin.Runtime, region, ownerID, serverID, serverIP, serverType, description string, port, weight int64) (*mqlAlicloudSlbBackendServer, error) {
	resource, err := CreateResource(runtime, "alicloud.slb.backendServer", map[string]*llx.RawData{
		"__id":        llx.StringData(backendServerKey(region, ownerID, serverID, port)),
		"serverId":    llx.StringData(serverID),
		"serverIp":    llx.StringData(serverIP),
		"port":        llx.IntData(port),
		"weight":      llx.IntData(weight),
		"type":        llx.StringData(serverType),
		"description": llx.StringData(description),
	})
	if err != nil {
		return nil, err
	}
	mqlServer := resource.(*mqlAlicloudSlbBackendServer)
	mqlServer.region = region
	return mqlServer, nil
}

// mqlAlicloudSlbBackendServerInternal caches the region the backend was listed
// in, which its instance reference needs.
type mqlAlicloudSlbBackendServerInternal struct {
	region string
}

func (r *mqlAlicloudSlbBackendServer) ecsInstance() (*mqlAlicloudEcsInstance, error) {
	if !backendIsEcs(r.Type.Data) {
		r.EcsInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveBackendEcsInstance(r.MqlRuntime, r.region, r.ServerId.Data, &r.EcsInstance)
}

// backends lists the servers attached directly to the load balancer, as opposed
// to those reached through one of its vServer groups.
func (r *mqlAlicloudSlbLoadBalancer) backends() ([]any, error) {
	servers, err := r.fetchBackendServers()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, s := range servers {
		if s == nil || s.ServerId == nil {
			continue
		}
		mqlServer, err := newSlbBackendServer(r.MqlRuntime, r.region, r.LoadBalancerId.Data,
			tea.StringValue(s.ServerId), tea.StringValue(s.ServerIp), tea.StringValue(s.Type),
			tea.StringValue(s.Description), 0, int64(tea.Int32Value(s.Weight)))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServer)
	}
	return res, nil
}

// fetchBackendServers loads the load balancer's directly attached backends.
// Both the deprecated backendServers dict list and the typed backends list read
// through it, so querying them together costs one call rather than two.
func (r *mqlAlicloudSlbLoadBalancer) fetchBackendServers() ([]*slbclient.DescribeLoadBalancerAttributeResponseBodyBackendServersBackendServer, error) {
	if r.backendsFetched.Load() {
		return r.cacheBackends, nil
	}
	r.backendsLock.Lock()
	defer r.backendsLock.Unlock()
	if r.backendsFetched.Load() {
		return r.cacheBackends, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlbClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeLoadBalancerAttribute(&slbclient.DescribeLoadBalancerAttributeRequest{
		RegionId:       new(r.region),
		LoadBalancerId: new(r.LoadBalancerId.Data),
	})
	if err != nil {
		return nil, err
	}

	servers := []*slbclient.DescribeLoadBalancerAttributeResponseBodyBackendServersBackendServer{}
	if resp != nil && resp.Body != nil && resp.Body.BackendServers != nil {
		servers = append(servers, resp.Body.BackendServers.BackendServer...)
	}
	r.cacheBackends = servers
	r.backendsFetched.Store(true)
	return r.cacheBackends, nil
}

func (r *mqlAlicloudSlbLoadBalancer) vServerGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlbClient(r.region)
	if err != nil {
		return nil, err
	}

	resp, err := client.DescribeVServerGroups(&slbclient.DescribeVServerGroupsRequest{
		RegionId:       new(r.region),
		LoadBalancerId: new(r.LoadBalancerId.Data),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.VServerGroups == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, g := range resp.Body.VServerGroups.VServerGroup {
		if g == nil || g.VServerGroupId == nil {
			continue
		}
		tags := map[string]any{}
		if g.Tags != nil {
			for _, t := range g.Tags.Tag {
				if t == nil || tea.StringValue(t.TagKey) == "" {
					continue
				}
				tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
			}
		}

		groupID := tea.StringValue(g.VServerGroupId)
		resource, err := CreateResource(r.MqlRuntime, "alicloud.slb.vServerGroup", map[string]*llx.RawData{
			"__id":             llx.StringData(r.region + "/" + groupID),
			"vServerGroupId":   llx.StringData(groupID),
			"vServerGroupName": llx.StringDataPtr(g.VServerGroupName),
			"loadBalancerId":   llx.StringData(r.LoadBalancerId.Data),
			"regionId":         llx.StringData(r.region),
			"serverCount":      llx.IntData(tea.Int64Value(g.ServerCount)),
			"createTime":       llx.TimeDataPtr(slbParseTime(g.CreateTime)),
			"tags":             llx.MapData(tags, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (r *mqlAlicloudSlbVServerGroup) id() (string, error) {
	return r.RegionId.Data + "/" + r.VServerGroupId.Data, nil
}

// backends lists the servers in the vServer group. The group summary carries
// only a count, so the members come from a per-group detail call.
func (r *mqlAlicloudSlbVServerGroup) backends() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	region := r.RegionId.Data
	client, err := conn.SlbClient(region)
	if err != nil {
		return nil, err
	}

	resp, err := client.DescribeVServerGroupAttribute(&slbclient.DescribeVServerGroupAttributeRequest{
		RegionId:       new(region),
		VServerGroupId: new(r.VServerGroupId.Data),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.BackendServers == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, s := range resp.Body.BackendServers.BackendServer {
		if s == nil || s.ServerId == nil {
			continue
		}
		mqlServer, err := newSlbBackendServer(r.MqlRuntime, region, r.VServerGroupId.Data,
			tea.StringValue(s.ServerId), tea.StringValue(s.ServerIp), tea.StringValue(s.Type),
			tea.StringValue(s.Description), int64(tea.Int32Value(s.Port)), int64(tea.Int32Value(s.Weight)))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServer)
	}
	return res, nil
}

// vServerGroup resolves the group a listener forwards to. A listener that sends
// traffic to the load balancer's default backends names no group, and a group
// can be deleted while its listener is still being read, so both resolve to
// null rather than failing the listener list.
func (r *mqlAlicloudSlbListener) vServerGroup() (*mqlAlicloudSlbVServerGroup, error) {
	groupID := r.VServerGroupId.Data
	if groupID == "" || r.parentLoadBalancer == nil {
		r.VServerGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	groups := r.parentLoadBalancer.GetVServerGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	for _, entry := range groups.Data {
		group, ok := entry.(*mqlAlicloudSlbVServerGroup)
		if !ok {
			continue
		}
		if group.VServerGroupId.Data == groupID {
			return group, nil
		}
	}
	log.Debug().Str("vServerGroupId", groupID).
		Msg("alicloud> listener names a vServer group that is not on its load balancer")
	r.VServerGroup.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
