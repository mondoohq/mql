// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/recordsets"
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/zones"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.dns.zone ----

func (r *mqlOpenstackDnsZone) id() (string, error) {
	return "openstack.dns.zone/" + r.Id.Data, nil
}

func initOpenstackDnsZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetDnsZones()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		z := raw.(*mqlOpenstackDnsZone)
		if z.Id.Data == id {
			return args, z, nil
		}
	}
	initSyntheticID("openstack.dns.zone", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) dnsZones() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.DNSClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := zones.List(client, zones.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := zones.ExtractZones(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, z := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.dns.zone", map[string]*llx.RawData{
			"__id":          llx.StringData("openstack.dns.zone/" + z.ID),
			"id":            llx.StringData(z.ID),
			"name":          llx.StringData(z.Name),
			"email":         llx.StringData(z.Email),
			"description":   llx.StringData(z.Description),
			"ttl":           llx.IntData(int64(z.TTL)),
			"serial":        llx.IntData(int64(z.Serial)),
			"status":        llx.StringData(z.Status),
			"action":        llx.StringData(z.Action),
			"type":          llx.StringData(z.Type),
			"masters":       stringSliceData(z.Masters),
			"createdAt":     llx.TimeDataPtr(timePtr(z.CreatedAt)),
			"updatedAt":     llx.TimeDataPtr(timePtr(z.UpdatedAt)),
			"transferredAt": llx.TimeDataPtr(timePtr(z.TransferredAt)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlOpenstackDnsZone).cacheProjectID = z.ProjectID
		out = append(out, res)
	}
	return out, nil
}

// mqlOpenstackDnsZoneInternal holds the owning project id that project()
// resolves.
type mqlOpenstackDnsZoneInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackDnsZone) project() (*mqlOpenstackProject, error) {
	if r.cacheProjectID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.project", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheProjectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}

func (r *mqlOpenstackDnsZone) recordsets() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.DNSClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := recordsets.ListByZone(client, r.Id.Data, recordsets.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := recordsets.ExtractRecordSets(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, rs := range items {
		res, err := CreateResource(r.MqlRuntime, "openstack.dns.recordset", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.dns.recordset/" + rs.ID),
			"id":          llx.StringData(rs.ID),
			"name":        llx.StringData(rs.Name),
			"type":        llx.StringData(rs.Type),
			"ttl":         llx.IntData(int64(rs.TTL)),
			"records":     stringSliceData(rs.Records),
			"description": llx.StringData(rs.Description),
			"status":      llx.StringData(rs.Status),
			"action":      llx.StringData(rs.Action),
			"createdAt":   llx.TimeDataPtr(timePtr(rs.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(timePtr(rs.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlOpenstackDnsRecordset).cacheZoneID = rs.ZoneID
		out = append(out, res)
	}
	return out, nil
}

// mqlOpenstackDnsRecordsetInternal holds the owning zone id that zone()
// resolves.
type mqlOpenstackDnsRecordsetInternal struct {
	cacheZoneID string
}

// ---- openstack.dns.recordset ----

func (r *mqlOpenstackDnsRecordset) id() (string, error) {
	return "openstack.dns.recordset/" + r.Id.Data, nil
}

func initOpenstackDnsRecordset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	initSyntheticID("openstack.dns.recordset", "id", args)
	return args, nil, nil
}

func (r *mqlOpenstackDnsRecordset) zone() (*mqlOpenstackDnsZone, error) {
	if r.cacheZoneID == "" {
		r.Zone.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.dns.zone", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheZoneID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackDnsZone), nil
}
