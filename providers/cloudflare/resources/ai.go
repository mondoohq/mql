// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"sort"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/ai_audit"
	"github.com/cloudflare/cloudflare-go/v7/ai_security"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

type mqlCloudflareZoneAiSecurityInternal struct {
	zoneID string
}

type mqlCloudflareZoneAiAuditInternal struct {
	zoneID string
	// The robots.txt fetch returns the agents alongside the status and sitemaps,
	// so the parsed map is kept from that one call rather than fetched again
	// when the user agents are asked for.
	userAgentRules map[string]ai_audit.RobotGetResponseUserAgent
}

// aiSecurity reports whether prompts and responses passing through the zone are
// inspected by AI Security for Apps.
func (c *mqlCloudflareZone) aiSecurity() (*mqlCloudflareZoneAiSecurity, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	settings, err := conn.Cf.AISecurity.Get(context.TODO(), ai_security.AISecurityGetParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		// AI Security is not on every plan, and a token without the scope has
		// established nothing about the zone. Null rather than a resource
		// reporting enabled=false, which is the finding itself.
		if isUnavailable(err) {
			c.AiSecurity.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.aiSecurity", map[string]*llx.RawData{
		"__id":    llx.StringData("cloudflare.zone.aiSecurity@" + c.Id.Data),
		"enabled": llx.BoolData(settings.Enabled),
	})
	if err != nil {
		return nil, err
	}

	sec := res.(*mqlCloudflareZoneAiSecurity)
	sec.zoneID = c.Id.Data
	return sec, nil
}

func (c *mqlCloudflareZoneAiSecurity) customTopics() ([]any, error) {
	if c.zoneID == "" {
		return []any{}, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	resp, err := conn.Cf.AISecurity.CustomTopics.Get(context.TODO(), ai_security.CustomTopicGetParams{
		ZoneID: cloudflare.F(c.zoneID),
	})
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(resp.Topics))
	for i := range resp.Topics {
		t := resp.Topics[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.aiSecurity.customTopic", map[string]*llx.RawData{
			"__id":  llx.StringData("cloudflare.zone.aiSecurity.customTopic@" + c.zoneID + "/" + t.Label),
			"label": llx.StringData(t.Label),
			"topic": llx.StringData(t.Topic),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

// aiAudit reports the zone's robots.txt as Cloudflare fetched and parsed it,
// which is what governs whether AI crawlers may read the site.
func (c *mqlCloudflareZone) aiAudit() (*mqlCloudflareZoneAiAudit, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	robots, err := conn.Cf.AIAudit.Robots.Get(context.TODO(), ai_audit.RobotGetParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		if isUnavailable(err) {
			c.AiAudit.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	sitemaps := make([]any, 0, len(robots.Sitemaps))
	for _, s := range robots.Sitemaps {
		sitemaps = append(sitemaps, s)
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.aiAudit", map[string]*llx.RawData{
		"__id":         llx.StringData("cloudflare.zone.aiAudit@" + c.Id.Data),
		"robotsStatus": llx.IntData(robots.Status),
		"sitemaps":     llx.ArrayData(sitemaps, types.String),
	})
	if err != nil {
		return nil, err
	}

	audit := res.(*mqlCloudflareZoneAiAudit)
	audit.zoneID = c.Id.Data
	audit.userAgentRules = robots.UserAgents
	return audit, nil
}

func (c *mqlCloudflareZoneAiAudit) userAgents() ([]any, error) {
	// The agents came back with the status and sitemaps, so there is nothing
	// left to fetch here.
	names := sortedUserAgentNames(c.userAgentRules)

	results := make([]any, 0, len(names))
	for _, name := range names {
		ua := c.userAgentRules[name]

		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.aiAudit.userAgent", map[string]*llx.RawData{
			"__id":                 llx.StringData("cloudflare.zone.aiAudit.userAgent@" + c.zoneID + "/" + name),
			"userAgent":            llx.StringData(name),
			"allow":                llx.ArrayData(strAnySlice(ua.Allow), types.String),
			"disallow":             llx.ArrayData(strAnySlice(ua.Disallow), types.String),
			"crawlDelay":           llx.FloatData(ua.CrawlDelay),
			"contentSignalAiTrain": llx.StringData(string(ua.ContentSignals.AITrain)),
			"contentSignalAiInput": llx.StringData(string(ua.ContentSignals.AIInput)),
			"contentSignalSearch":  llx.StringData(string(ua.ContentSignals.Search)),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

// sortedUserAgentNames orders the agents robots.txt named. The API returns them
// as a map, and Go randomizes map iteration, so without this two scans of the
// same unchanged zone produce the list in different orders.
func sortedUserAgentNames(rules map[string]ai_audit.RobotGetResponseUserAgent) []string {
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func strAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}
