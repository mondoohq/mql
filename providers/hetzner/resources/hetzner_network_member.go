// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (m *mqlHetznerNetwork) members() ([]any, error) {
	c := conn(m.MqlRuntime)
	network := &hcloud.Network{ID: m.Id.Data}
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.NetworkMember, *hcloud.Response, error) {
		return c.Client().Network.ListMembers(ctx(), network, hcloud.NetworkMemberListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, member := range items {
		if member == nil {
			continue
		}
		res, err := newMqlHetznerNetworkMember(m, member)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlHetznerNetworkMemberInternal keeps the network the member was listed
// from and the attached resource's id, which server and loadBalancer resolve
// against the project's cached lists.
type mqlHetznerNetworkMemberInternal struct {
	cacheNetwork  *mqlHetznerNetwork
	cacheMemberID int64
}

// networkMemberID builds the cache key for a member. A resource is attached to
// a network at most once, so the network id plus the member's type and id is
// unique and stable. The type is part of the key because a server and a load
// balancer can share a numeric id.
func networkMemberID(networkID int64, memberType string, memberID int64) string {
	return fmt.Sprintf("hetzner.network/%d/member/%s/%d", networkID, memberType, memberID)
}

func newMqlHetznerNetworkMember(network *mqlHetznerNetwork, member *hcloud.NetworkMember) (*mqlHetznerNetworkMember, error) {
	aliases := make([]string, 0, len(member.AliasIPs))
	for _, ip := range member.AliasIPs {
		if ip == nil {
			continue
		}
		aliases = append(aliases, ip.String())
	}
	res, err := CreateResource(network.MqlRuntime, "hetzner.network.member", map[string]*llx.RawData{
		"__id":     llx.StringData(networkMemberID(network.Id.Data, string(member.Type), member.ID)),
		"type":     llx.StringData(string(member.Type)),
		"ip":       llx.StringData(ipString(member.IP)),
		"aliasIps": stringArrayData(aliases),
		"subnet":   llx.StringData(ipNetString(member.Subnet)),
		"status":   llx.StringData(string(member.Status)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerNetworkMember)
	m.cacheNetwork = network
	m.cacheMemberID = member.ID
	return m, nil
}

func (m *mqlHetznerNetworkMember) network() (*mqlHetznerNetwork, error) {
	if m.cacheNetwork == nil {
		m.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return m.cacheNetwork, nil
}

// server resolves a server member against the once-cached project server
// list rather than one GetByID per member.
func (m *mqlHetznerNetworkMember) server() (*mqlHetznerServer, error) {
	if m.Type.Data != string(hcloud.NetworkMemberTypeServer) || m.cacheMemberID == 0 {
		m.Server.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	servers, err := h.allServers()
	if err != nil {
		return nil, err
	}
	for _, s := range servers {
		if s != nil && s.ID == m.cacheMemberID {
			return newMqlHetznerServer(m.MqlRuntime, s)
		}
	}
	// Detached or deleted between the member listing and the server listing.
	m.Server.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// loadBalancer resolves a load balancer member against the once-cached
// project load balancer list.
func (m *mqlHetznerNetworkMember) loadBalancer() (*mqlHetznerLoadBalancer, error) {
	if m.Type.Data != string(hcloud.NetworkMemberTypeLoadBalancer) || m.cacheMemberID == 0 {
		m.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	lbs, err := h.allLoadBalancers()
	if err != nil {
		return nil, err
	}
	for _, lb := range lbs {
		if lb != nil && lb.ID == m.cacheMemberID {
			return newMqlHetznerLoadBalancer(m.MqlRuntime, lb)
		}
	}
	m.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
