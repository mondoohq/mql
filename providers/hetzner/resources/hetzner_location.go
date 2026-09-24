// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlHetznerLocation) id() (string, error) {
	return fmt.Sprintf("hetzner.location/%d", r.Id.Data), nil
}

func (h *mqlHetzner) locations() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Location, *hcloud.Response, error) {
		return c.Client().Location.List(ctx(), hcloud.LocationListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, loc := range items {
		res, err := newMqlHetznerLocation(h.MqlRuntime, loc)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerLocation(runtime *plugin.Runtime, loc *hcloud.Location) (*mqlHetznerLocation, error) {
	res, err := CreateResource(runtime, "hetzner.location", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("hetzner.location/%d", loc.ID)),
		"id":          llx.IntData(loc.ID),
		"name":        llx.StringData(loc.Name),
		"description": llx.StringData(loc.Description),
		"country":     llx.StringData(loc.Country),
		"city":        llx.StringData(loc.City),
		"latitude":    llx.FloatData(loc.Latitude),
		"longitude":   llx.FloatData(loc.Longitude),
		"networkZone": llx.StringData(string(loc.NetworkZone)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerLocation), nil
}

func (m *mqlHetznerLocation) servers() ([]any, error) {
	locID := m.Id.Data
	return serversMatching(m.MqlRuntime, func(s *hcloud.Server) bool {
		return s.Location != nil && s.Location.ID == locID
	})
}

func initHetznerLocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "location")
	if err != nil {
		return nil, nil, err
	}
	loc, _, err := conn(runtime).Client().Location.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if loc == nil {
		return nil, nil, notFoundErr("location", id)
	}
	res, err := newMqlHetznerLocation(runtime, loc)
	return args, res, err
}

// locationMatches reports whether a resource's location is the given one. The
// pointer is nil for resources the API returns without a location, which is
// not a match: reporting them under every location would inflate a residency
// answer with resources whose location was never read.
func locationMatches(loc *hcloud.Location, id int64) bool {
	return loc != nil && loc.ID == id
}

func volumesInLocation(volumes []*hcloud.Volume, id int64) []*hcloud.Volume {
	out := []*hcloud.Volume{}
	for _, v := range volumes {
		if v != nil && locationMatches(v.Location, id) {
			out = append(out, v)
		}
	}
	return out
}

func loadBalancersInLocation(balancers []*hcloud.LoadBalancer, id int64) []*hcloud.LoadBalancer {
	out := []*hcloud.LoadBalancer{}
	for _, lb := range balancers {
		if lb != nil && locationMatches(lb.Location, id) {
			out = append(out, lb)
		}
	}
	return out
}

func primaryIPsInLocation(ips []*hcloud.PrimaryIP, id int64) []*hcloud.PrimaryIP {
	out := []*hcloud.PrimaryIP{}
	for _, p := range ips {
		if p != nil && locationMatches(p.Location, id) {
			out = append(out, p)
		}
	}
	return out
}

// floatingIPsInHomeLocation filters on HomeLocation, not Location: a floating
// IP has no location of its own and can be routed to a server elsewhere, so
// the home location is where the address lives rather than where its traffic
// currently lands.
func floatingIPsInHomeLocation(ips []*hcloud.FloatingIP, id int64) []*hcloud.FloatingIP {
	out := []*hcloud.FloatingIP{}
	for _, f := range ips {
		if f != nil && locationMatches(f.HomeLocation, id) {
			out = append(out, f)
		}
	}
	return out
}

func storageBoxesInLocation(boxes []*hcloud.StorageBox, id int64) []*hcloud.StorageBox {
	out := []*hcloud.StorageBox{}
	for _, sb := range boxes {
		if sb != nil && locationMatches(sb.Location, id) {
			out = append(out, sb)
		}
	}
	return out
}

func (m *mqlHetznerLocation) volumes() ([]any, error) {
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allVolumes()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, v := range volumesInLocation(items, m.Id.Data) {
		res, err := newMqlHetznerVolume(m.MqlRuntime, v)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerLocation) loadBalancers() ([]any, error) {
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allLoadBalancers()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, lb := range loadBalancersInLocation(items, m.Id.Data) {
		res, err := newMqlHetznerLoadBalancer(m.MqlRuntime, lb)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerLocation) primaryIps() ([]any, error) {
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allPrimaryIPs()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, p := range primaryIPsInLocation(items, m.Id.Data) {
		res, err := newMqlHetznerPrimaryIp(m.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerLocation) floatingIps() ([]any, error) {
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allFloatingIPs()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, f := range floatingIPsInHomeLocation(items, m.Id.Data) {
		res, err := newMqlHetznerFloatingIp(m.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerLocation) storageBoxes() ([]any, error) {
	h, err := hetznerNamespace(m.MqlRuntime)
	if err != nil {
		return nil, err
	}
	items, err := h.allStorageBoxes()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, sb := range storageBoxesInLocation(items, m.Id.Data) {
		res, err := newMqlHetznerStorageBox(m.MqlRuntime, sb)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
