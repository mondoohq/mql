// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlHetznerZone) id() (string, error) {
	return fmt.Sprintf("hetzner.zone/%d", r.Id.Data), nil
}

func (h *mqlHetzner) zones() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Zone, *hcloud.Response, error) {
		return c.Client().Zone.List(ctx(), hcloud.ZoneListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, z := range items {
		res, err := newMqlHetznerZone(h.MqlRuntime, z)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// zonePrimaryNameserverDicts renders the primaries a secondary zone transfers
// from. The TSIG key is a shared secret and is never surfaced as queryable
// data; only whether one is configured is reported, so an unauthenticated
// transfer stays auditable.
func zonePrimaryNameserverDicts(nameservers []hcloud.ZonePrimaryNameserver) []any {
	out := make([]any, 0, len(nameservers))
	for _, ns := range nameservers {
		out = append(out, map[string]any{
			"address":        ns.Address,
			"port":           int64(ns.Port),
			"tsigAlgorithm":  string(ns.TSIGAlgorithm),
			"tsigConfigured": ns.TSIGKey != "",
		})
	}
	return out
}

func newMqlHetznerZone(runtime *plugin.Runtime, z *hcloud.Zone) (*mqlHetznerZone, error) {
	primaryNS := zonePrimaryNameserverDicts(z.PrimaryNameservers)

	res, err := CreateResource(runtime, "hetzner.zone", map[string]*llx.RawData{
		"__id":                 llx.StringData(fmt.Sprintf("hetzner.zone/%d", z.ID)),
		"id":                   llx.IntData(z.ID),
		"name":                 llx.StringData(z.Name),
		"mode":                 llx.StringData(string(z.Mode)),
		"status":               llx.StringData(string(z.Status)),
		"ttl":                  llx.IntData(int64(z.TTL)),
		"recordCount":          llx.IntData(int64(z.RecordCount)),
		"registrar":            llx.StringData(string(z.Registrar)),
		"primaryNameservers":   dictArrayData(primaryNS),
		"assignedNameservers":  stringArrayData(z.AuthoritativeNameservers.Assigned),
		"delegatedNameservers": stringArrayData(z.AuthoritativeNameservers.Delegated),
		"delegationStatus":     llx.StringData(string(z.AuthoritativeNameservers.DelegationStatus)),
		"delegationLastCheck":  llx.TimeDataPtr(timePtr(z.AuthoritativeNameservers.DelegationLastCheck)),
		"protection":           llx.DictData(protectionDict(z.Protection.Delete)),
		"labels":               labelData(z.Labels),
		"created":              llx.TimeDataPtr(timePtr(z.Created)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerZone), nil
}

func initHetznerZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "zone")
	if err != nil {
		return nil, nil, err
	}
	z, _, err := conn(runtime).Client().Zone.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if z == nil {
		return nil, nil, notFoundErr("zone", id)
	}
	res, err := newMqlHetznerZone(runtime, z)
	return args, res, err
}

// zonefile exports what Hetzner's nameservers actually serve for the zone.
//
// This is a separate request per zone, so it stays a computed field and is
// never populated while listing zones. An export failure propagates rather
// than reporting an empty zone file: an empty string would read as a zone that
// publishes nothing, which is a claim we did not verify.
func (m *mqlHetznerZone) zonefile() (string, error) {
	c := conn(m.MqlRuntime)
	res, _, err := c.Client().Zone.ExportZonefile(ctx(), &hcloud.Zone{ID: m.Id.Data})
	if err != nil {
		return "", err
	}
	return res.Zonefile, nil
}

func (m *mqlHetznerZone) rrsets() ([]any, error) {
	c := conn(m.MqlRuntime)
	zone := &hcloud.Zone{ID: m.Id.Data}
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.ZoneRRSet, *hcloud.Response, error) {
		return c.Client().Zone.ListRRSets(ctx(), zone, hcloud.ZoneRRSetListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, rr := range items {
		res, err := newMqlHetznerZoneRrset(m.MqlRuntime, m.Id.Data, rr)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlHetznerZoneRrsetInternal keeps the raw record set so entries() can build
// one resource per value without re-listing the zone.
type mqlHetznerZoneRrsetInternal struct {
	cacheRrset  *hcloud.ZoneRRSet
	cacheZoneID int64
}

// mqlHetznerZoneRrsetRecordInternal carries the record set a value belongs to.
// The record's own type lives there, and resolving a target starts by asking
// whether that type carries an address at all.
type mqlHetznerZoneRrsetRecordInternal struct {
	cacheZoneID int64
	cacheRrset  *hcloud.ZoneRRSet
}

func (r *mqlHetznerZoneRrset) id() (string, error) {
	return fmt.Sprintf("hetzner.zone.rrset/%d/%s", r.cacheZoneID, r.Id.Data), nil
}

func newMqlHetznerZoneRrset(runtime *plugin.Runtime, zoneID int64, rr *hcloud.ZoneRRSet) (*mqlHetznerZoneRrset, error) {
	res, err := CreateResource(runtime, "hetzner.zone.rrset", map[string]*llx.RawData{
		"__id":       llx.StringData(fmt.Sprintf("hetzner.zone.rrset/%d/%s", zoneID, rr.ID)),
		"id":         llx.StringData(rr.ID),
		"name":       llx.StringData(rr.Name),
		"type":       llx.StringData(string(rr.Type)),
		"ttl":        llx.IntDataDefault(rr.TTL, 0),
		"protection": llx.DictData(map[string]any{"change": rr.Protection.Change}),
		"labels":     labelData(rr.Labels),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerZoneRrset)
	m.cacheRrset = rr
	m.cacheZoneID = zoneID
	return m, nil
}

func (m *mqlHetznerZoneRrset) zone() (*mqlHetznerZone, error) {
	ref, err := NewResource(m.MqlRuntime, "hetzner.zone", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheZoneID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerZone), nil
}
