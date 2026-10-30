// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	slbclient "github.com/alibabacloud-go/slb-20140515/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// slbParseTime parses an RFC3339 timestamp returned by the SLB API, returning
// nil when the input is nil or cannot be parsed.
func slbParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// slbLoadBalancerTags flattens the SLB describe-load-balancers tag list into a
// string map.
func slbLoadBalancerTags(tags *slbclient.DescribeLoadBalancersResponseBodyLoadBalancersLoadBalancerTags) map[string]any {
	res := map[string]any{}
	if tags == nil {
		return res
	}
	for _, t := range tags.Tag {
		if t == nil || t.TagKey == nil {
			continue
		}
		res[*t.TagKey] = tea.StringValue(t.TagValue)
	}
	return res
}

// slbListenerConfig marshals the protocol-specific listener config that is set
// on the listener into a generic dict. Exactly one of the four config structs
// is populated per listener, keyed by the listener protocol.
func slbListenerConfig(l *slbclient.DescribeLoadBalancerListenersResponseBodyListeners) any {
	var cfg any
	switch {
	case l.HTTPListenerConfig != nil:
		cfg = l.HTTPListenerConfig
	case l.HTTPSListenerConfig != nil:
		cfg = l.HTTPSListenerConfig
	case l.TCPListenerConfig != nil:
		cfg = l.TCPListenerConfig
	case l.UDPListenerConfig != nil:
		cfg = l.UDPListenerConfig
	default:
		return nil
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func (r *mqlAlicloudSlb) id() (string, error) {
	return "alicloud.slb", nil
}

type mqlAlicloudSlbLoadBalancerInternal struct {
	region         string
	cacheRegion    string
	cacheVpcID     string
	cacheVswitchID string

	backendsLock    sync.Mutex
	backendsFetched atomic.Bool
	cacheBackends   []*slbclient.DescribeLoadBalancerAttributeResponseBodyBackendServersBackendServer
}

func (r *mqlAlicloudSlb) loadBalancers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.SlbClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		firstPage := true
		for {
			resp, err := client.DescribeLoadBalancers(&slbclient.DescribeLoadBalancersRequest{
				RegionId:   new(region),
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil {
				// A first-page error means the region has no SLB or the
				// credential lacks access there — skip it. A later-page error
				// means the region is reachable and the failure is real; surface
				// it rather than silently truncating the list (matches ALB/NLB).
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil || resp.Body.LoadBalancers == nil {
				break
			}

			lbs := resp.Body.LoadBalancers.LoadBalancer
			for _, lb := range lbs {
				if lb == nil || lb.LoadBalancerId == nil {
					continue
				}

				mqlLb, err := newSlbLoadBalancer(r.MqlRuntime, region, lb)
				if err != nil {
					return nil, err
				}
				// DescribeLoadBalancers returns tags inline, so the filter costs
				// nothing beyond the listing already made
				if filteredOutByTags(conn, mqlLb.Tags.Data) {
					continue
				}
				res = append(res, mqlLb)
			}

			if len(lbs) == 0 || int(pageNumber)*int(pageSize) >= int(tea.Int32Value(resp.Body.TotalCount)) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// newSlbLoadBalancer builds a fully populated alicloud.slb.loadBalancer from a
// DescribeLoadBalancers list item within a region. It is shared by the
// loadBalancers list accessor and the by-id init so both produce identical
// resources.
func newSlbLoadBalancer(runtime *plugin.Runtime, region string, lb *slbclient.DescribeLoadBalancersResponseBodyLoadBalancersLoadBalancer) (*mqlAlicloudSlbLoadBalancer, error) {
	resource, err := CreateResource(runtime, "alicloud.slb.loadBalancer", map[string]*llx.RawData{
		"__id":                         llx.StringDataPtr(lb.LoadBalancerId),
		"loadBalancerId":               llx.StringDataPtr(lb.LoadBalancerId),
		"loadBalancerName":             llx.StringDataPtr(lb.LoadBalancerName),
		"address":                      llx.StringDataPtr(lb.Address),
		"addressType":                  llx.StringDataPtr(lb.AddressType),
		"addressIPVersion":             llx.StringDataPtr(lb.AddressIPVersion),
		"status":                       llx.StringDataPtr(lb.LoadBalancerStatus),
		"regionId":                     llx.StringDataPtr(lb.RegionId),
		"masterZoneId":                 llx.StringDataPtr(lb.MasterZoneId),
		"slaveZoneId":                  llx.StringDataPtr(lb.SlaveZoneId),
		"networkType":                  llx.StringDataPtr(lb.NetworkType),
		"internetChargeType":           llx.StringDataPtr(lb.InternetChargeType),
		"instanceChargeType":           llx.StringDataPtr(lb.InstanceChargeType),
		"loadBalancerSpec":             llx.StringDataPtr(lb.LoadBalancerSpec),
		"payType":                      llx.StringDataPtr(lb.PayType),
		"bandwidth":                    llx.IntDataPtr(lb.Bandwidth),
		"createTime":                   llx.TimeDataPtr(slbParseTime(lb.CreateTime)),
		"deleteProtection":             llx.StringDataPtr(lb.DeleteProtection),
		"modificationProtectionStatus": llx.StringDataPtr(lb.ModificationProtectionStatus),
		"modificationProtectionReason": llx.StringDataPtr(lb.ModificationProtectionReason),
		"resourceGroupId":              llx.StringDataPtr(lb.ResourceGroupId),
		"tags":                         llx.MapData(slbLoadBalancerTags(lb.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlLb := resource.(*mqlAlicloudSlbLoadBalancer)
	mqlLb.region = region
	mqlLb.cacheRegion = region
	mqlLb.cacheVpcID = tea.StringValue(lb.VpcId)
	mqlLb.cacheVswitchID = tea.StringValue(lb.VSwitchId)
	return mqlLb, nil
}

// initAlicloudSlbLoadBalancer resolves a CLB instance by its native load
// balancer id within a region, reusing an already-listed instance from the
// resource cache. It also backs the discovered slb asset, which scopes the
// connection to one load balancer.
func initAlicloudSlbLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered CLB asset, resolve the load balancer the asset is scoped to
	args = scopedInitArgs(runtime, args, connection.OptionSlbID, "loadBalancerId")

	lbID, err := requiredStringArg(args, "loadBalancerId", "alicloud.slb.loadBalancer")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.slb.loadBalancer")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.slb.loadBalancer\x00" + lbID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlbClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeLoadBalancers(&slbclient.DescribeLoadBalancersRequest{
		RegionId:       new(region),
		LoadBalancerId: new(lbID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil && resp.Body.LoadBalancers != nil {
		for _, lb := range resp.Body.LoadBalancers.LoadBalancer {
			if lb == nil || tea.StringValue(lb.LoadBalancerId) != lbID {
				continue
			}
			res, err := newSlbLoadBalancer(runtime, region, lb)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.slb.loadBalancer %q not found in region %q", lbID, region)
}

func (r *mqlAlicloudSlbLoadBalancer) id() (string, error) {
	return r.LoadBalancerId.Data, nil
}

func (r *mqlAlicloudSlbLoadBalancer) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudSlbLoadBalancer) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.cacheRegion, r.cacheVswitchID)
}

func (r *mqlAlicloudSlbLoadBalancer) listeners() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	lbId := r.LoadBalancerId.Data
	client, err := conn.SlbClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	var nextToken *string
	for {
		resp, err := client.DescribeLoadBalancerListeners(&slbclient.DescribeLoadBalancerListenersRequest{
			RegionId:       new(r.region),
			LoadBalancerId: []*string{new(lbId)},
			MaxResults:     tea.Int32(100),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, l := range resp.Body.Listeners {
			if l == nil {
				continue
			}

			protocol := tea.StringValue(l.ListenerProtocol)
			port := tea.Int32Value(l.ListenerPort)

			args := map[string]*llx.RawData{
				"__id":                llx.StringData(fmt.Sprintf("%s/%s/%d", lbId, protocol, port)),
				"loadBalancerId":      llx.StringData(lbId),
				"protocol":            llx.StringDataPtr(l.ListenerProtocol),
				"listenerPort":        llx.IntDataPtr(l.ListenerPort),
				"backendServerPort":   llx.IntDataPtr(l.BackendServerPort),
				"status":              llx.StringDataPtr(l.Status),
				"bandwidth":           llx.IntDataPtr(l.Bandwidth),
				"scheduler":           llx.StringDataPtr(l.Scheduler),
				"description":         llx.StringDataPtr(l.Description),
				"aclStatus":           llx.StringDataPtr(l.AclStatus),
				"aclType":             llx.StringDataPtr(l.AclType),
				"aclId":               llx.StringDataPtr(l.AclId),
				"aclIds":              llx.ArrayData(llx.TArr2Raw(convertSlbStrPtrs(l.AclIds)), types.String),
				"vServerGroupId":      llx.StringDataPtr(l.VServerGroupId),
				"config":              llx.DictData(slbListenerConfig(l)),
				"tlsCipherPolicy":     llx.StringDataPtr(nil),
				"serverCertificateId": llx.StringDataPtr(nil),
				"caCertificateId":     llx.StringDataPtr(nil),
				"enableHttp2":         llx.StringDataPtr(nil),
			}

			if https := l.HTTPSListenerConfig; https != nil {
				args["tlsCipherPolicy"] = llx.StringDataPtr(https.TLSCipherPolicy)
				args["serverCertificateId"] = llx.StringDataPtr(https.ServerCertificateId)
				args["caCertificateId"] = llx.StringDataPtr(https.CACertificateId)
				args["enableHttp2"] = llx.StringDataPtr(https.EnableHttp2)
			}

			listener, err := CreateResource(r.MqlRuntime, "alicloud.slb.listener", args)
			if err != nil {
				return nil, err
			}
			listener.(*mqlAlicloudSlbListener).parentLoadBalancer = r
			res = append(res, listener)
		}

		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = resp.Body.NextToken
	}
	return res, nil
}

func (r *mqlAlicloudSlbLoadBalancer) backendServers() ([]any, error) {
	servers, err := r.fetchBackendServers()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, s := range servers {
		if s == nil {
			continue
		}
		res = append(res, map[string]any{
			"serverId":    tea.StringValue(s.ServerId),
			"serverIp":    tea.StringValue(s.ServerIp),
			"weight":      int64(tea.Int32Value(s.Weight)),
			"type":        tea.StringValue(s.Type),
			"description": tea.StringValue(s.Description),
		})
	}
	return res, nil
}

// mqlAlicloudSlbListenerInternal holds the load balancer the listener was
// listed from. A listener exists only as a child of its load balancer, so
// carrying the parent from the listing context resolves the reference without
// an API call and without a by-id lookup that the SLB resource does not have.
type mqlAlicloudSlbListenerInternal struct {
	parentLoadBalancer *mqlAlicloudSlbLoadBalancer
}

func (r *mqlAlicloudSlbListener) loadBalancer() (*mqlAlicloudSlbLoadBalancer, error) {
	if r.parentLoadBalancer == nil {
		r.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.parentLoadBalancer, nil
}

func (r *mqlAlicloudSlbListener) id() (string, error) {
	return fmt.Sprintf("%s/%s/%d", r.LoadBalancerId.Data, r.Protocol.Data, r.ListenerPort.Data), nil
}

// convertSlbStrPtrs dereferences a slice of string pointers, skipping nil
// elements.
func convertSlbStrPtrs(in []*string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		out = append(out, *s)
	}
	return out
}
