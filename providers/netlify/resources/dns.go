// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/types"
)

// mqlNetlifyDnsZoneInternal caches the site the zone was created for, which is
// only present on the zone payload.
type mqlNetlifyDnsZoneInternal struct {
	cacheSiteID string
}

type dnsZoneRecord struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Dedicated   bool        `json:"dedicated"`
	Ipv6Enabled bool        `json:"ipv6_enabled"`
	DNSServers  []string    `json:"dns_servers"`
	AccountID   string      `json:"account_id"`
	AccountSlug string      `json:"account_slug"`
	SiteID      string      `json:"site_id"`
	CreatedAt   netlifyTime `json:"created_at"`
	UpdatedAt   netlifyTime `json:"updated_at"`
}

func newNetlifyDnsZone(runtime *plugin.Runtime, rec *dnsZoneRecord) (*mqlNetlifyDnsZone, error) {
	res, err := CreateResource(runtime, "netlify.dnsZone", map[string]*llx.RawData{
		"id":          llx.StringData(rec.ID),
		"name":        llx.StringData(rec.Name),
		"dedicated":   llx.BoolData(rec.Dedicated),
		"ipv6Enabled": llx.BoolData(rec.Ipv6Enabled),
		"dnsServers":  llx.ArrayData(strSliceToAny(rec.DNSServers), types.String),
		"createdAt":   llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":   llx.TimeDataPtr(rec.UpdatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	zone := res.(*mqlNetlifyDnsZone)
	zone.cacheSiteID = rec.SiteID
	return zone, nil
}

// initNetlifyDnsZone resolves a zone by its identifier.
func initNetlifyDnsZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	zoneID := ""
	if data, ok := args["id"]; ok {
		if s, ok := data.Value.(string); ok {
			zoneID = s
		}
	}
	if zoneID == "" {
		return nil, nil, errors.New("netlify.dnsZone requires an id")
	}

	c := netlifyConn(runtime)

	var rec dnsZoneRecord
	if err := c.Get(context.Background(), "/dns_zones/"+url.PathEscape(zoneID), nil, &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		rec.ID = zoneID
	}

	zone, err := newNetlifyDnsZone(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, zone, nil
}

func (z *mqlNetlifyDnsZone) id() (string, error) {
	return z.Id.Data, z.Id.Error
}

// site resolves the site the zone was created for. A zone added for a domain
// that is not attached to a site has none.
//
// The match runs against the site list the root resource has already fetched,
// so a query over many zones does not read one site per zone. A site outside
// the scope the connection is narrowed to is absent from that list, so a miss
// falls back to the direct lookup.
func (z *mqlNetlifyDnsZone) site() (*mqlNetlifySite, error) {
	if z.cacheSiteID == "" {
		z.Site.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(z.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if site, ok := findCachedResource(root.GetSites(), netlifySiteID, z.cacheSiteID); ok {
		return site, nil
	}

	res, err := NewResource(z.MqlRuntime, "netlify.site", map[string]*llx.RawData{
		"id": llx.StringData(z.cacheSiteID),
	})
	if err != nil {
		// A zone can outlive the site it was created for, and a site in
		// another account is not readable with this token.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			z.Site.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNetlifySite), nil
}

type dnsRecordRecord struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      int64  `json:"ttl"`
	Priority int64  `json:"priority"`
	Flag     int64  `json:"flag"`
	Tag      string `json:"tag"`
	Managed  bool   `json:"managed"`
}

func (z *mqlNetlifyDnsZone) records() ([]any, error) {
	c := netlifyConn(z.MqlRuntime)

	records, err := connection.GetPaged[dnsRecordRecord](context.Background(), c,
		"/dns_zones/"+url.PathEscape(z.Id.Data)+"/dns_records", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			z.Records = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		record, err := CreateResource(z.MqlRuntime, "netlify.dnsZone.record", map[string]*llx.RawData{
			"id":       llx.StringData(rec.ID),
			"hostname": llx.StringData(rec.Hostname),
			"type":     llx.StringData(rec.Type),
			"value":    llx.StringData(rec.Value),
			"ttl":      llx.IntData(rec.TTL),
			"priority": llx.IntData(rec.Priority),
			"flag":     llx.IntData(rec.Flag),
			"tag":      llx.StringData(rec.Tag),
			"managed":  llx.BoolData(rec.Managed),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, record)
	}
	return res, nil
}

func (r *mqlNetlifyDnsZoneRecord) id() (string, error) {
	return r.Id.Data, r.Id.Error
}

// dnsZones lists the Netlify-managed zones serving the site.
func (s *mqlNetlifySite) dnsZones() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[dnsZoneRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/dns", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.DnsZones = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		zone, err := newNetlifyDnsZone(s.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, zone)
	}
	return res, nil
}
