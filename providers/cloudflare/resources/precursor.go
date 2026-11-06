// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"encoding/json"
	"strconv"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/precursor"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// precursorLegacy is the retired enforcement-mode shape of the Precursor
// configuration. cloudflare-go v7.14.0 dropped it from the typed response, so
// it is decoded from the raw body to keep the deprecated fields working for as
// long as Cloudflare still sends it.
type precursorLegacy struct {
	DefaultMode      *string               `json:"default_mode"`
	EnforcementRules []precursorLegacyRule `json:"enforcement_rules"`
}

type precursorLegacyRule struct {
	ID          string `json:"id"`
	Expression  string `json:"expression"`
	Mode        string `json:"mode"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// decodePrecursorLegacy reads the retired fields from a raw configuration
// body. A body without them, or one that does not parse, yields the zero
// value, so the deprecated fields read as null and empty.
func decodePrecursorLegacy(raw string) precursorLegacy {
	var legacy precursorLegacy
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &legacy)
	}
	return legacy
}

// precursorRuleKey returns a rule's cache key. Cloudflare assigns each rule an
// id, but the list is ordered and its order is semantic, so a rule that
// arrives without one still needs a distinct key. Falling back to the ordinal
// keeps two such rules from sharing a cache entry, where the second would
// silently report the first one's values.
func precursorRuleKey(id string, i int) string {
	if id == "" {
		return "#" + strconv.Itoa(i)
	}
	return id
}

// precursor reports the zone's Precursor configuration: the detection mode,
// whether an interstitial is shown, and the ordered rule overrides.
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

	rules := make([]any, 0, len(cfg.Rules))
	for i := range cfg.Rules {
		rule := cfg.Rules[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.precursor.rule", map[string]*llx.RawData{
			"__id":             llx.StringData("cloudflare.zone.precursor.rule@" + c.Id.Data + "/" + precursorRuleKey(rule.ID, i)),
			"id":               llx.StringData(rule.ID),
			"expression":       llx.StringData(rule.Expression),
			"showInterstitial": llx.BoolData(rule.ShowInterstitial),
			"description":      optionalString(rule.Description),
			"enabled":          llx.BoolData(rule.Enabled),
		})
		if err != nil {
			return nil, err
		}
		rules = append(rules, res)
	}

	legacy := decodePrecursorLegacy(cfg.JSON.RawJSON())
	legacyRules := make([]any, 0, len(legacy.EnforcementRules))
	for i := range legacy.EnforcementRules {
		rule := legacy.EnforcementRules[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.precursor.enforcementRule", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.zone.precursor.enforcementRule@" + c.Id.Data + "/" + precursorRuleKey(rule.ID, i)),
			"id":          llx.StringData(rule.ID),
			"expression":  llx.StringData(rule.Expression),
			"mode":        llx.StringData(rule.Mode),
			"description": llx.StringData(rule.Description),
			"enabled":     llx.BoolData(rule.Enabled),
		})
		if err != nil {
			return nil, err
		}
		legacyRules = append(legacyRules, res)
	}

	mode := llx.NilData
	if cfg.Mode != "" {
		mode = llx.StringData(string(cfg.Mode))
	}
	showInterstitial := llx.NilData
	if !cfg.JSON.ShowInterstitial.IsMissing() && !cfg.JSON.ShowInterstitial.IsNull() {
		showInterstitial = llx.BoolData(cfg.ShowInterstitial)
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.precursor", map[string]*llx.RawData{
		"__id":             llx.StringData("cloudflare.zone.precursor@" + c.Id.Data),
		"mode":             mode,
		"showInterstitial": showInterstitial,
		"rules":            llx.ArrayData(rules, types.Resource("cloudflare.zone.precursor.rule")),
		"defaultMode":      llx.StringDataPtr(legacy.DefaultMode),
		"enforcementRules": llx.ArrayData(legacyRules, types.Resource("cloudflare.zone.precursor.enforcementRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCloudflareZonePrecursor), nil
}
