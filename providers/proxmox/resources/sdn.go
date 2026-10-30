// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

func (r *mqlProxmox) sdnZones() ([]any, error) {
	conn := proxmoxConn(r)
	zones, err := conn.GetSDNZones()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(zones))
	for i, z := range zones {
		res, err := CreateResource(r.MqlRuntime, "proxmox.sdn.zone", map[string]*llx.RawData{
			"zone":       llx.StringData(z.Zone),
			"type":       llx.StringData(z.Type),
			"ipam":       llx.StringData(z.IPAM),
			"mtu":        llx.IntData(int64(z.MTU)),
			"nodes":      llx.StringData(z.Nodes),
			"dns":        llx.StringData(z.DNS),
			"dnsZone":    llx.StringData(z.DNSZone),
			"reverseDns": llx.StringData(z.ReverseDNS),
			"pending":    llx.BoolData(z.Pending == 1),
			"state":      llx.StringData(z.State),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// VNets
// ---------------------------------------------------------------------------

func (r *mqlProxmox) sdnVnets() ([]any, error) {
	conn := proxmoxConn(r)
	vnets, err := conn.GetSDNVNets()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(vnets))
	for i, v := range vnets {
		res, err := CreateResource(r.MqlRuntime, "proxmox.sdn.vnet", map[string]*llx.RawData{
			"vnet":      llx.StringData(v.VNet),
			"zone":      llx.StringData(v.Zone),
			"alias":     llx.StringData(v.Alias),
			"tag":       llx.IntData(int64(v.Tag)),
			"vlanAware": llx.BoolData(v.VLANAware == 1),
			"type":      llx.StringData(v.Type),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxSdnVnet) zoneRef() (*mqlProxmoxSdnZone, error) {
	if r.Zone.Data == "" {
		r.ZoneRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.sdn.zone", map[string]*llx.RawData{
		"zone": llx.StringData(r.Zone.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxSdnZone), nil
}

func (r *mqlProxmoxSdnVnet) subnets() ([]any, error) {
	return sdnSubnetsForVNet(r.MqlRuntime, r.Vnet.Data)
}

// ---------------------------------------------------------------------------
// Subnets (scoped to a vnet)
// ---------------------------------------------------------------------------

func sdnSubnetsForVNet(runtime *plugin.Runtime, vnet string) ([]any, error) {
	conn := runtime.Connection.(*connection.PveConnection)
	subs, err := conn.GetSDNSubnets(vnet)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(subs))
	for i, s := range subs {
		id := s.ID
		if id == "" {
			// older PVE versions don't echo an explicit id; reconstruct it
			// from vnet + cidr so cache keys remain stable across calls.
			id = vnet + "/" + s.CIDR
		}
		cidr := s.CIDR
		if cidr == "" {
			cidr = s.Subnet
		}
		res, err := CreateResource(runtime, "proxmox.sdn.subnet", map[string]*llx.RawData{
			"id":            llx.StringData(id),
			"cidr":          llx.StringData(cidr),
			"gateway":       llx.StringData(s.Gateway),
			"snat":          llx.BoolData(s.SNAT == 1),
			"dnsZonePrefix": llx.StringData(s.DNSZonePrefix),
			"vnet":          llx.StringData(s.VNet),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxSdnSubnet) vnetRef() (*mqlProxmoxSdnVnet, error) {
	if r.Vnet.Data == "" {
		r.VnetRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.sdn.vnet", map[string]*llx.RawData{
		"vnet": llx.StringData(r.Vnet.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxSdnVnet), nil
}

// ---------------------------------------------------------------------------
// VNet firewall
// ---------------------------------------------------------------------------

func (r *mqlProxmoxSdnVnet) firewallRules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	rules, readable, err := conn.GetSDNVNetFirewallRules(r.Vnet.Data)
	if err != nil {
		return nil, err
	}
	if !readable {
		// An empty rule list on a vnet whose firewall could not be read would
		// pass an audit looking for a segmentation rule set, so report that
		// nothing was read instead.
		r.FirewallRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return firewallRulesToResources(r.MqlRuntime, rules, "vnet/"+r.Vnet.Data)
}

func (r *mqlProxmoxSdnVnet) firewallOptions() (*mqlProxmoxFirewallOptions, error) {
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	opts, readable, err := conn.GetSDNVNetFirewallOptions(r.Vnet.Data)
	if err != nil {
		return nil, err
	}
	if !readable {
		r.FirewallOptions.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := firewallOptionsToResource(r.MqlRuntime, opts, "vnet/"+r.Vnet.Data)
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxFirewallOptions), nil
}
