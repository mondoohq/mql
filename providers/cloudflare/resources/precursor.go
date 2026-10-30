// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"strconv"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/precursor"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// precursor reports the zone's Precursor enforcement posture: the mode applied
// to requests matching no rule, and the ordered overrides evaluated ahead of it.
func (c *mqlCloudflareZone) precursor() (*mqlCloudflareZonePrecursor, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	cfg, err := conn.Cf.Precursor.Get(context.TODO(), precursor.PrecursorGetParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		if isUnavailable(err) {
			c.Precursor.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	rules := make([]any, 0, len(cfg.EnforcementRules))
	for i := range cfg.EnforcementRules {
		rule := cfg.EnforcementRules[i]

		// Cloudflare assigns each rule an id, but the list is ordered and its
		// order is semantic, so a rule that arrives without one still needs a
		// distinct key. Falling back to the ordinal keeps two such rules from
		// sharing a cache entry, where the second would silently report the
		// first one's expression and mode.
		key := rule.ID
		if key == "" {
			key = "#" + strconv.Itoa(i)
		}

		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.precursor.enforcementRule", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.zone.precursor.enforcementRule@" + c.Id.Data + "/" + key),
			"id":          llx.StringData(rule.ID),
			"expression":  llx.StringData(rule.Expression),
			"mode":        llx.StringData(string(rule.Mode)),
			"description": llx.StringData(rule.Description),
			"enabled":     llx.BoolData(rule.Enabled),
		})
		if err != nil {
			return nil, err
		}
		rules = append(rules, res)
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.precursor", map[string]*llx.RawData{
		"__id":             llx.StringData("cloudflare.zone.precursor@" + c.Id.Data),
		"defaultMode":      llx.StringData(string(cfg.DefaultMode)),
		"enforcementRules": llx.ArrayData(rules, types.Resource("cloudflare.zone.precursor.enforcementRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCloudflareZonePrecursor), nil
}
