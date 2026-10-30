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

// allPrimaryIPs, allFloatingIPs and allLoadBalancers mirror allServers: one
// project-wide list per scan, cached on the namespace resource and shared by
// every record that resolves a target.
//
// Resolution walks these lists rather than a hash index because an IPv6 match
// is a containment test against an assigned /64, which a lookup cannot answer.
// The lists are small enough that the walk is free next to the API calls.
func (h *mqlHetzner) allPrimaryIPs() ([]*hcloud.PrimaryIP, error) {
	h.primaryIPsOnce.Do(func() {
		c := conn(h.MqlRuntime)
		h.primaryIPsList, h.primaryIPsErr = paginate(func(opts hcloud.ListOpts) ([]*hcloud.PrimaryIP, *hcloud.Response, error) {
			return c.Client().PrimaryIP.List(ctx(), hcloud.PrimaryIPListOpts{ListOpts: opts})
		})
	})
	return h.primaryIPsList, h.primaryIPsErr
}

func (h *mqlHetzner) allFloatingIPs() ([]*hcloud.FloatingIP, error) {
	h.floatingIPsOnce.Do(func() {
		c := conn(h.MqlRuntime)
		h.floatingIPsList, h.floatingIPsErr = paginate(func(opts hcloud.ListOpts) ([]*hcloud.FloatingIP, *hcloud.Response, error) {
			return c.Client().FloatingIP.List(ctx(), hcloud.FloatingIPListOpts{ListOpts: opts})
		})
	})
	return h.floatingIPsList, h.floatingIPsErr
}

func (h *mqlHetzner) allLoadBalancers() ([]*hcloud.LoadBalancer, error) {
	h.loadBalancersOnce.Do(func() {
		c := conn(h.MqlRuntime)
		h.loadBalancersList, h.loadBalancersErr = paginate(func(opts hcloud.ListOpts) ([]*hcloud.LoadBalancer, *hcloud.Response, error) {
			return c.Client().LoadBalancer.List(ctx(), hcloud.LoadBalancerListOpts{ListOpts: opts})
		})
	})
	return h.loadBalancersList, h.loadBalancersErr
}

// projectFootprints collects the public address footprint of every resource in
// the project a DNS record could point at.
func projectFootprints(h *mqlHetzner) ([]publicAddress, error) {
	servers, err := h.allServers()
	if err != nil {
		return nil, err
	}
	primaries, err := h.allPrimaryIPs()
	if err != nil {
		return nil, err
	}
	floating, err := h.allFloatingIPs()
	if err != nil {
		return nil, err
	}
	balancers, err := h.allLoadBalancers()
	if err != nil {
		return nil, err
	}

	out := make([]publicAddress, 0, len(servers)+len(primaries)+len(floating)+len(balancers))
	for _, s := range servers {
		out = append(out, serverPublicAddress(s.PublicNet))
	}
	for _, p := range primaries {
		out = append(out, singleAddress(p.IP, p.Network))
	}
	for _, f := range floating {
		out = append(out, singleAddress(f.IP, f.Network))
	}
	for _, lb := range balancers {
		out = append(out, loadBalancerPublicAddress(lb.PublicNet))
	}
	return out, nil
}

// zoneRecord is one value of one record set, carried with the identity needed
// to build the resource for it.
type zoneRecord struct {
	zoneID int64
	rrset  *hcloud.ZoneRRSet
	record hcloud.ZoneRRSetRecord
}

// allZoneRecords flattens every record of every record set in every zone. It
// costs one Zone.List plus one ListRRSets per zone, paid once per scan and
// shared by the reverse edge on each server.
func (h *mqlHetzner) allZoneRecords() ([]zoneRecord, error) {
	h.zoneRecordsOnce.Do(func() {
		h.zoneRecordsList, h.zoneRecordsErr = listZoneRecords(h.MqlRuntime)
	})
	return h.zoneRecordsList, h.zoneRecordsErr
}

func listZoneRecords(runtime *plugin.Runtime) ([]zoneRecord, error) {
	c := conn(runtime)
	zones, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Zone, *hcloud.Response, error) {
		return c.Client().Zone.List(ctx(), hcloud.ZoneListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}

	out := []zoneRecord{}
	for _, z := range zones {
		rrsets, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.ZoneRRSet, *hcloud.Response, error) {
			return c.Client().Zone.ListRRSets(ctx(), z, hcloud.ZoneRRSetListOpts{ListOpts: opts})
		})
		if err != nil {
			return nil, err
		}
		for _, rr := range rrsets {
			for _, rec := range rr.Records {
				out = append(out, zoneRecord{zoneID: z.ID, rrset: rr, record: rec})
			}
		}
	}
	return out, nil
}

func newMqlHetznerZoneRrsetRecord(runtime *plugin.Runtime, zoneID int64, rr *hcloud.ZoneRRSet, rec hcloud.ZoneRRSetRecord) (*mqlHetznerZoneRrsetRecord, error) {
	res, err := CreateResource(runtime, "hetzner.zone.rrset.record", map[string]*llx.RawData{
		"__id":    llx.StringData(fmt.Sprintf("hetzner.zone.rrset.record/%d/%s/%s", zoneID, rr.ID, rec.Value)),
		"value":   llx.StringData(rec.Value),
		"comment": llx.StringData(rec.Comment),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerZoneRrsetRecord)
	m.cacheZoneID = zoneID
	m.cacheRrset = rr
	return m, nil
}

func (m *mqlHetznerZoneRrset) entries() ([]any, error) {
	if m.cacheRrset == nil {
		m.Entries.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	out := make([]any, 0, len(m.cacheRrset.Records))
	for _, rec := range m.cacheRrset.Records {
		res, err := newMqlHetznerZoneRrsetRecord(m.MqlRuntime, m.cacheZoneID, m.cacheRrset, rec)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// recordAddr returns the address this record publishes and whether its type
// carries one at all.
func (m *mqlHetznerZoneRrsetRecord) recordAddr() (net.IP, bool) {
	if m.cacheRrset == nil {
		return nil, false
	}
	return recordAddress(string(m.cacheRrset.Type), m.Value.Data)
}

func (m *mqlHetznerZoneRrsetRecord) rrset() (*mqlHetznerZoneRrset, error) {
	if m.cacheRrset == nil {
		m.Rrset.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlHetznerZoneRrset(m.MqlRuntime, m.cacheZoneID, m.cacheRrset)
}

func (m *mqlHetznerZoneRrsetRecord) targetsProjectResource() (bool, error) {
	addr, carriesAddress := m.recordAddr()
	if !carriesAddress {
		m.TargetsProjectResource.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if addr == nil {
		// An address record whose value does not parse resolves to nothing the
		// project holds, which is what false already reports.
		return false, nil
	}

	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return false, err
	}
	footprints, err := projectFootprints(h)
	if err != nil {
		return false, err
	}
	for _, f := range footprints {
		if f.holds(addr) {
			return true, nil
		}
	}
	return false, nil
}

func (m *mqlHetznerZoneRrsetRecord) servers() ([]any, error) {
	addr, carriesAddress := m.recordAddr()
	if !carriesAddress {
		m.Servers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return serversMatching(m.MqlRuntime, func(s *hcloud.Server) bool {
		return serverPublicAddress(s.PublicNet).holds(addr)
	})
}

func (m *mqlHetznerZoneRrsetRecord) primaryIps() ([]any, error) {
	addr, carriesAddress := m.recordAddr()
	if !carriesAddress {
		m.PrimaryIps.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allPrimaryIPs()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, p := range items {
		if !singleAddress(p.IP, p.Network).holds(addr) {
			continue
		}
		res, err := newMqlHetznerPrimaryIp(m.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerZoneRrsetRecord) floatingIps() ([]any, error) {
	addr, carriesAddress := m.recordAddr()
	if !carriesAddress {
		m.FloatingIps.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allFloatingIPs()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, f := range items {
		if !singleAddress(f.IP, f.Network).holds(addr) {
			continue
		}
		res, err := newMqlHetznerFloatingIp(m.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerZoneRrsetRecord) loadBalancers() ([]any, error) {
	addr, carriesAddress := m.recordAddr()
	if !carriesAddress {
		m.LoadBalancers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allLoadBalancers()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, lb := range items {
		if !loadBalancerPublicAddress(lb.PublicNet).holds(addr) {
			continue
		}
		res, err := newMqlHetznerLoadBalancer(m.MqlRuntime, lb)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// dnsRecords is the reverse of the record target edges: the A and AAAA records
// published in the project's own zones that resolve to this server. Records in
// zones hosted elsewhere are not visible to the API and so not reported.
func (m *mqlHetznerServer) dnsRecords() ([]any, error) {
	addr := serverPublicAddress(m.cachePublicNet)
	if addr.empty() {
		// A server without public networking is not reachable by an address
		// record, so nothing can point at it. That is genuinely none.
		return []any{}, nil
	}

	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	records, err := h.allZoneRecords()
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, zr := range records {
		ip, carriesAddress := recordAddress(string(zr.rrset.Type), zr.record.Value)
		if !carriesAddress || !addr.holds(ip) {
			continue
		}
		res, err := newMqlHetznerZoneRrsetRecord(m.MqlRuntime, zr.zoneID, zr.rrset, zr.record)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
