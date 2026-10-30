// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/firewall"
	"github.com/cloudflare/cloudflare-go/v7/zones"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareIpAccessRule) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// ipAccessRules lists the IP Access rules that apply to the zone. The zone
// endpoint returns the account's own rules alongside the zone's, which is what
// makes the zone view the one that answers "what can reach this zone without
// passing the WAF".
func (c *mqlCloudflareZone) ipAccessRules() ([]any, error) {
	return fetchIPAccessRules(c.MqlRuntime, firewall.AccessRuleListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	}, "zone/"+c.Id.Data)
}

// ipAccessRules lists the account-wide IP Access rules, which apply to every
// zone the account owns.
func (c *mqlCloudflareAccount) ipAccessRules() ([]any, error) {
	return fetchIPAccessRules(c.MqlRuntime, firewall.AccessRuleListParams{
		AccountID: cloudflare.F(c.Id.Data),
	}, "account/"+c.Id.Data)
}

// fetchIPAccessRules walks the paginated IP Access rules endpoint for one scope.
//
// scopeKey qualifies the cache key. The same account-level rule is returned by
// both the account listing and the listing of every zone the account owns, and
// the two are different answers ("the account defines this" versus "this
// applies here"), so they must not collapse onto one cached resource.
func fetchIPAccessRules(runtime *plugin.Runtime, params firewall.AccessRuleListParams, scopeKey string) ([]any, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	result := []any{}
	iter := conn.Cf.Firewall.AccessRules.ListAutoPaging(context.TODO(), params)
	for iter.Next() {
		rec := iter.Current()

		allowedModes := make([]any, 0, len(rec.AllowedModes))
		for _, m := range rec.AllowedModes {
			allowedModes = append(allowedModes, string(m))
		}

		res, err := CreateResource(runtime, "cloudflare.ipAccessRule", map[string]*llx.RawData{
			"__id":         llx.StringData("cloudflare.ipAccessRule@" + scopeKey + "/" + rec.ID),
			"id":           llx.StringData(rec.ID),
			"mode":         llx.StringData(string(rec.Mode)),
			"target":       llx.StringData(string(rec.Configuration.Target)),
			"value":        llx.StringData(rec.Configuration.Value),
			"notes":        llx.StringData(rec.Notes),
			"scopeType":    llx.StringData(string(rec.Scope.Type)),
			"allowedModes": llx.ArrayData(allowedModes, types.String),
			"createdOn":    timeOrNil(rec.CreatedOn),
			"modifiedOn":   timeOrNil(rec.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

func (c *mqlCloudflareZoneLockdown) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// lockdowns lists the zone's Zone Lockdown rules, each pinning a set of URL
// patterns to named addresses.
func (c *mqlCloudflareZone) lockdowns() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	result := []any{}
	iter := conn.Cf.Firewall.Lockdowns.ListAutoPaging(context.TODO(), firewall.LockdownListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		rec := iter.Current()

		configurations := make([]any, 0, len(rec.Configurations))
		for i := range rec.Configurations {
			cfg := rec.Configurations[i]
			configurations = append(configurations, map[string]any{
				"target": string(cfg.Target),
				"value":  cfg.Value,
			})
		}

		urls := make([]any, 0, len(rec.URLs))
		for _, u := range rec.URLs {
			urls = append(urls, string(u))
		}

		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.lockdown", map[string]*llx.RawData{
			"__id":           llx.StringData("cloudflare.zone.lockdown@" + c.Id.Data + "/" + rec.ID),
			"id":             llx.StringData(rec.ID),
			"description":    llx.StringData(rec.Description),
			"paused":         llx.BoolData(rec.Paused),
			"urls":           llx.ArrayData(urls, types.String),
			"configurations": llx.ArrayData(configurations, types.Dict),
			"createdOn":      timeOrNil(rec.CreatedOn),
			"modifiedOn":     timeOrNil(rec.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

// hold reports the zone's registrar hold. Without one, a zone removed from this
// account can be re-added to any other Cloudflare account and served from
// there.
//
// The whole resource reports null when the hold state cannot be read, rather
// than a resource reading `enabled: false`, which would report an unreadable
// zone as one standing wide open to being reclaimed.
func (c *mqlCloudflareZone) hold() (*mqlCloudflareZoneHold, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	resp, err := conn.Cf.Zones.Holds.Get(context.TODO(), zones.HoldGetParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		if isUnavailable(err) {
			c.Hold.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.hold", map[string]*llx.RawData{
		"__id":              llx.StringData("cloudflare.zone.hold@" + c.Id.Data),
		"enabled":           llx.BoolData(resp.Hold),
		"holdAfter":         cfTimeString(resp.HoldAfter),
		"includeSubdomains": llx.StringData(resp.IncludeSubdomains),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlCloudflareZoneHold), nil
}
