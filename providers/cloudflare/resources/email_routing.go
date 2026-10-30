// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// emailRoutingDNSRecord is a suggested DNS record returned by the email-routing
// DNS endpoint, decoded via the client's generic Get.
type emailRoutingDNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int64  `json:"ttl"`
	Priority *int   `json:"priority"`
}

type mqlCloudflareZoneEmailRoutingInternal struct {
	zoneID   string
	zoneName string

	dnsLock    sync.Mutex
	dnsFetched bool
	dnsCache   []emailRoutingDNSRecord

	zoneNameOnce sync.Once
	zoneNameErr  error
}

func (c *mqlCloudflareZone) emailRouting() (*mqlCloudflareZoneEmailRouting, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result struct {
			Name     string     `json:"name"`
			Enabled  bool       `json:"enabled"`
			Status   string     `json:"status"`
			Created  *time.Time `json:"created"`
			Modified *time.Time `json:"modified"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/email/routing", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.EmailRouting.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	settings := env.Result
	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.emailRouting", map[string]*llx.RawData{
		"__id":       llx.StringData("cloudflare.zone.emailRouting@" + c.Id.Data),
		"enabled":    llx.BoolData(settings.Enabled),
		"status":     llx.StringData(settings.Status),
		"name":       llx.StringData(settings.Name),
		"createdAt":  llx.TimeDataPtr(settings.Created),
		"modifiedAt": llx.TimeDataPtr(settings.Modified),
	})
	if err != nil {
		return nil, err
	}

	er := res.(*mqlCloudflareZoneEmailRouting)
	er.zoneID = c.Id.Data
	er.zoneName = c.GetName().Data
	return er, nil
}

// dnsRecords returns the suggested DNS records reported by the email-routing
// settings endpoint. These are the MX/SPF/DKIM records Cloudflare expects in
// place for routing to work. We expose them as raw dicts so callers can
// inspect record type, name, content, and TTL alongside `mxConfigured`,
// `spfConfigured`, and `dmarcConfigured` derived booleans.
func (c *mqlCloudflareZoneEmailRouting) dnsRecords() ([]any, error) {
	records, err := c.fetchSuggestedDNSRecords()
	if err != nil {
		return nil, err
	}

	result := make([]any, 0, len(records))
	for i := range records {
		r := records[i]
		entry := map[string]any{
			"type":     r.Type,
			"name":     r.Name,
			"content":  r.Content,
			"ttl":      r.TTL,
			"priority": int64(0),
		}
		if r.Priority != nil {
			entry["priority"] = int64(*r.Priority)
		}
		result = append(result, entry)
	}
	return result, nil
}

func (c *mqlCloudflareZoneEmailRouting) mxConfigured() (bool, error) {
	records, err := c.fetchSuggestedDNSRecords()
	if err != nil {
		return false, err
	}
	for _, r := range records {
		if strings.EqualFold(r.Type, "MX") {
			return true, nil
		}
	}
	return false, nil
}

func (c *mqlCloudflareZoneEmailRouting) spfConfigured() (bool, error) {
	records, err := c.fetchSuggestedDNSRecords()
	if err != nil {
		return false, err
	}
	for _, r := range records {
		if strings.EqualFold(r.Type, "TXT") && strings.Contains(strings.ToLower(r.Content), "v=spf1") {
			return true, nil
		}
	}
	return false, nil
}

// dmarcConfigured queries the zone's existing DNS records (not the suggested
// ones — Cloudflare doesn't auto-generate DMARC for email routing) and looks
// for a `_dmarc.<zone>` TXT record starting with `v=DMARC1`. It filters
// server-side by record name so we get only the candidate record(s) regardless
// of pagination.
func (c *mqlCloudflareZoneEmailRouting) dmarcConfigured() (bool, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	if c.zoneID == "" {
		return false, nil
	}

	zoneName, err := c.resolveZoneName()
	if err != nil {
		return false, err
	}

	dmarcName := "_dmarc"
	if zoneName != "" {
		dmarcName = "_dmarc." + zoneName
	}

	var env struct {
		Result []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/dns_records?type=TXT&name=%s", c.zoneID, url.QueryEscape(dmarcName))
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		// Degrade to "not configured" when the token can't read DNS records,
		// matching the rest of this file rather than erroring the field.
		if isUnavailable(err) {
			return false, nil
		}
		return false, err
	}

	for _, r := range env.Result {
		if !strings.EqualFold(r.Name, dmarcName) {
			continue
		}
		if strings.Contains(strings.ToLower(r.Content), "v=dmarc1") {
			return true, nil
		}
	}
	return false, nil
}

// resolveZoneName returns the zone name, fetching it from the API if it wasn't
// populated when the email routing resource was created (e.g., when the zone
// resource was reached via lazy init). The result is cached for the lifetime
// of the resource via sync.Once for race-free initialization.
func (c *mqlCloudflareZoneEmailRouting) resolveZoneName() (string, error) {
	c.zoneNameOnce.Do(func() {
		if c.zoneName != "" || c.zoneID == "" {
			return
		}

		conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
		var env struct {
			Result struct {
				Name string `json:"name"`
			} `json:"result"`
		}
		uri := fmt.Sprintf("zones/%s", c.zoneID)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
			if isUnavailable(err) {
				return
			}
			c.zoneNameErr = err
			return
		}
		c.zoneName = env.Result.Name
	})
	return c.zoneName, c.zoneNameErr
}

func (c *mqlCloudflareZoneEmailRouting) fetchSuggestedDNSRecords() ([]emailRoutingDNSRecord, error) {
	if c.dnsFetched {
		return c.dnsCache, nil
	}
	c.dnsLock.Lock()
	defer c.dnsLock.Unlock()
	if c.dnsFetched {
		return c.dnsCache, nil
	}

	if c.zoneID == "" {
		c.dnsFetched = true
		return nil, nil
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	var env struct {
		Result []emailRoutingDNSRecord `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/email/routing/dns", c.zoneID)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		// A token without DNS-record read (403/404) degrades to "no suggested
		// records" so mxConfigured/spfConfigured read false instead of erroring;
		// cache the empty result since the permission won't change mid-scan.
		if isUnavailable(err) {
			c.dnsCache = nil
			c.dnsFetched = true
			return nil, nil
		}
		// Don't cache transient errors — leave dnsFetched=false so the next
		// call retries instead of returning the stale failure forever.
		return nil, err
	}
	c.dnsCache = env.Result
	c.dnsFetched = true
	return c.dnsCache, nil
}
