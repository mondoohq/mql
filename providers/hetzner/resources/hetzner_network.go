// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerNetworkInternal struct {
	cacheServers       []*hcloud.Server
	cacheLoadBalancers []*hcloud.LoadBalancer
	cacheRoutes        []hcloud.NetworkRoute
}

func (r *mqlHetznerNetwork) id() (string, error) {
	return fmt.Sprintf("hetzner.network/%d", r.Id.Data), nil
}

func (h *mqlHetzner) networks() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Network, *hcloud.Response, error) {
		return c.Client().Network.List(ctx(), hcloud.NetworkListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, n := range items {
		res, err := newMqlHetznerNetwork(h.MqlRuntime, n)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerNetwork(runtime *plugin.Runtime, n *hcloud.Network) (*mqlHetznerNetwork, error) {
	subnets := make([]any, 0, len(n.Subnets))
	for _, s := range n.Subnets {
		subnets = append(subnets, map[string]any{
			"type":        string(s.Type),
			"ipRange":     ipNetString(s.IPRange),
			"networkZone": string(s.NetworkZone),
			"gateway":     ipString(s.Gateway),
			// 0 when the subnet is not attached to a vSwitch. A non-zero value
			// bridges the network to hardware outside this project.
			"vswitchId": s.VSwitchID,
		})
	}
	routes := make([]any, 0, len(n.Routes))
	for _, r := range n.Routes {
		routes = append(routes, map[string]any{
			"destination": ipNetString(r.Destination),
			"gateway":     ipString(r.Gateway),
		})
	}

	res, err := CreateResource(runtime, "hetzner.network", map[string]*llx.RawData{
		"__id":                  llx.StringData(fmt.Sprintf("hetzner.network/%d", n.ID)),
		"id":                    llx.IntData(n.ID),
		"name":                  llx.StringData(n.Name),
		"ipRange":               llx.StringData(ipNetString(n.IPRange)),
		"created":               llx.TimeDataPtr(timePtr(n.Created)),
		"subnets":               dictArrayData(subnets),
		"routes":                dictArrayData(routes),
		"exposeRoutesToVswitch": llx.BoolData(n.ExposeRoutesToVSwitch),
		"protection":            llx.DictData(protectionDict(n.Protection.Delete)),
		"labels":                labelData(n.Labels),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerNetwork)
	m.cacheServers = n.Servers
	m.cacheLoadBalancers = n.LoadBalancers
	m.cacheRoutes = n.Routes
	return m, nil
}

func initHetznerNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "network")
	if err != nil {
		return nil, nil, err
	}
	n, _, err := conn(runtime).Client().Network.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if n == nil {
		return nil, nil, notFoundErr("network", id)
	}
	res, err := newMqlHetznerNetwork(runtime, n)
	return args, res, err
}

func (m *mqlHetznerNetwork) servers() ([]any, error) {
	out := make([]any, 0, len(m.cacheServers))
	for _, s := range m.cacheServers {
		// Network.Servers is a list of partial Server objects (just IDs).
		// Use NewResource so an init-by-id can fully resolve them on demand.
		ref, err := NewResource(m.MqlRuntime, "hetzner.server", map[string]*llx.RawData{
			"id": llx.IntData(s.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerNetwork) loadBalancers() ([]any, error) {
	out := make([]any, 0, len(m.cacheLoadBalancers))
	for _, lb := range m.cacheLoadBalancers {
		ref, err := NewResource(m.MqlRuntime, "hetzner.loadBalancer", map[string]*llx.RawData{
			"id": llx.IntData(lb.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerNetwork) staticRoutes() ([]any, error) {
	out := make([]any, 0, len(m.cacheRoutes))
	for _, r := range m.cacheRoutes {
		res, err := newMqlHetznerNetworkRoute(m.MqlRuntime, m.Id.Data, r)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- network.route sub-resource ---

// mqlHetznerNetworkRouteInternal keeps the network the route belongs to and
// the raw gateway address, which gatewayServer resolves against the project's
// servers.
type mqlHetznerNetworkRouteInternal struct {
	cacheNetworkID int64
	cacheGateway   net.IP
}

func (r *mqlHetznerNetworkRoute) id() (string, error) {
	return networkRouteID(r.cacheNetworkID, r.Destination.Data), nil
}

// networkRouteID builds the cache key for a route. A network holds at most one
// route per destination, so the network id plus the destination CIDR is stable
// and unique.
func networkRouteID(networkID int64, destination string) string {
	return fmt.Sprintf("hetzner.network.route/%d/%s", networkID, destination)
}

func newMqlHetznerNetworkRoute(runtime *plugin.Runtime, networkID int64, r hcloud.NetworkRoute) (*mqlHetznerNetworkRoute, error) {
	destination := ipNetString(r.Destination)
	res, err := CreateResource(runtime, "hetzner.network.route", map[string]*llx.RawData{
		"__id":        llx.StringData(networkRouteID(networkID, destination)),
		"destination": llx.StringData(destination),
		"gateway":     llx.StringData(ipString(r.Gateway)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerNetworkRoute)
	m.cacheNetworkID = networkID
	m.cacheGateway = r.Gateway
	return m, nil
}

func (m *mqlHetznerNetworkRoute) network() (*mqlHetznerNetwork, error) {
	if m.cacheNetworkID == 0 {
		m.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(m.MqlRuntime, "hetzner.network", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheNetworkID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerNetwork), nil
}

// gatewayServer names the server carrying the route's traffic.
//
// It scans the once-cached project server list rather than resolving the
// gateway with a per-route NewResource: an init runs before the runtime cache
// is consulted, so a per-route lookup would turn one Server.List into one API
// call per route, and there is no endpoint that maps a private address to a
// server in the first place.
func (m *mqlHetznerNetworkRoute) gatewayServer() (*mqlHetznerServer, error) {
	if m.cacheGateway == nil {
		m.GatewayServer.State = plugin.StateIsSet | plugin.StateIsNull
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
	s := serverHoldingPrivateIP(servers, m.cacheNetworkID, m.cacheGateway)
	if s == nil {
		m.GatewayServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlHetznerServer(m.MqlRuntime, s)
}

// serverHoldingPrivateIP returns the server whose attachment to the given
// network holds addr, as either the interface address or an alias IP.
//
// The match is scoped to one network on purpose. Two networks in a project can
// carry overlapping IP ranges, so an address alone does not identify a server;
// only the address within the route's own network does.
func serverHoldingPrivateIP(servers []*hcloud.Server, networkID int64, addr net.IP) *hcloud.Server {
	if addr == nil {
		return nil
	}
	for _, s := range servers {
		if s == nil {
			continue
		}
		for _, p := range s.PrivateNet {
			if p.Network == nil || p.Network.ID != networkID {
				continue
			}
			if p.IP.Equal(addr) {
				return s
			}
			for _, alias := range p.Aliases {
				if alias.Equal(addr) {
					return s
				}
			}
		}
	}
	return nil
}
