// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/rulesets"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareZoneWafRule) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.RulesetId.Data + "/" + c.Id.Data, nil
}

// rulesetDetail mirrors the ruleset-detail response. cloudflare-go's typed
// rule struct doesn't expose the per-rule score_threshold we surface, so we read
// the ruleset detail via the client's generic Get and decode it ourselves.
//
// action_parameters, ratelimit, and logging stay as raw JSON: action_parameters
// in particular is polymorphic on the rule's action (a block rule's carries a
// response body, an execute rule's carries a ruleset id and overrides, a skip
// rule's carries phases and products), so decoding it into one struct here would
// make an unexpected shape fail the whole ruleset read. They are parsed
// separately and leniently below.
type rulesetDetail struct {
	Result struct {
		Version string `json:"version"`
		Rules   []struct {
			ID               string          `json:"id"`
			Action           string          `json:"action"`
			Expression       string          `json:"expression"`
			Description      string          `json:"description"`
			Ref              string          `json:"ref"`
			Enabled          bool            `json:"enabled"`
			ScoreThreshold   int64           `json:"score_threshold"`
			Version          string          `json:"version"`
			LastUpdated      time.Time       `json:"last_updated"`
			ActionParameters json.RawMessage `json:"action_parameters"`
			Ratelimit        json.RawMessage `json:"ratelimit"`
			Logging          json.RawMessage `json:"logging"`
		} `json:"rules"`
	} `json:"result"`
}

type (
	// wafRuleOverride is one entry of action_parameters.overrides.rules: a
	// substitution the deploying rule makes for a single rule of the managed
	// ruleset it executes.
	wafRuleOverride struct {
		ID               string `json:"id"`
		Action           string `json:"action"`
		Enabled          *bool  `json:"enabled"`
		ScoreThreshold   *int64 `json:"score_threshold"`
		SensitivityLevel string `json:"sensitivity_level"`
		Status           string `json:"status"`
	}

	// wafCategoryOverride is one entry of action_parameters.overrides.categories.
	wafCategoryOverride struct {
		Category string `json:"category"`
		Action   string `json:"action"`
		Enabled  *bool  `json:"enabled"`
	}

	// wafActionParameters is the subset of a rule's action_parameters that
	// decides whether the rule enforces anything: the overrides that can switch
	// off a deployed managed ruleset, and the skip targets that take traffic out
	// of the WAF entirely.
	wafActionParameters struct {
		OverrideAction           string
		OverrideEnabled          *bool
		OverrideSensitivityLevel string
		RuleOverrides            []wafRuleOverride
		CategoryOverrides        []wafCategoryOverride
		SkipPhases               []string
		SkipProducts             []string
		SkipRulesets             []string
		SkipRules                map[string][]string
	}

	// wafRatelimit is the rate-limit configuration of a ruleset rule. Every
	// field is a pointer so a rule that carries no ratelimit block reports null
	// rather than a threshold of zero, which would read as "no requests
	// allowed".
	wafRatelimit struct {
		Characteristics    []string `json:"characteristics"`
		Period             *int64   `json:"period"`
		RequestsPerPeriod  *int64   `json:"requests_per_period"`
		MitigationTimeout  *int64   `json:"mitigation_timeout"`
		CountingExpression string   `json:"counting_expression"`
		RequestsToOrigin   *bool    `json:"requests_to_origin"`
	}
)

// parseWafActionParameters decodes the parts of a rule's action_parameters that
// the schema exposes. It is deliberately lenient: an action_parameters shape it
// does not recognize yields a zero value rather than an error, so a new or
// unexpected rule action never fails the read of the ruleset it belongs to.
func parseWafActionParameters(raw json.RawMessage) wafActionParameters {
	var out wafActionParameters
	if len(raw) == 0 {
		return out
	}

	var params struct {
		Overrides *struct {
			Action           string                `json:"action"`
			Enabled          *bool                 `json:"enabled"`
			SensitivityLevel string                `json:"sensitivity_level"`
			Categories       []wafCategoryOverride `json:"categories"`
			Rules            []wafRuleOverride     `json:"rules"`
		} `json:"overrides"`
		Phases   []string        `json:"phases"`
		Products []string        `json:"products"`
		Rulesets []string        `json:"rulesets"`
		Rules    json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return out
	}

	if o := params.Overrides; o != nil {
		out.OverrideAction = o.Action
		out.OverrideEnabled = o.Enabled
		out.OverrideSensitivityLevel = o.SensitivityLevel
		out.RuleOverrides = o.Rules
		out.CategoryOverrides = o.Categories
	}
	out.SkipPhases = params.Phases
	out.SkipProducts = params.Products
	out.SkipRulesets = params.Rulesets

	// `rules` is a skip rule's map of ruleset id to skipped rule ids. Other
	// actions do not use the key; if one ever does with a different shape, the
	// decode fails here and leaves the field null instead of failing the query.
	if len(params.Rules) > 0 {
		var skipRules map[string][]string
		if err := json.Unmarshal(params.Rules, &skipRules); err == nil {
			out.SkipRules = skipRules
		}
	}

	return out
}

// parseWafRatelimit decodes a rule's ratelimit block, returning nil when the
// rule carries none or the block cannot be decoded.
func parseWafRatelimit(raw json.RawMessage) *wafRatelimit {
	if len(raw) == 0 {
		return nil
	}
	var rl wafRatelimit
	if err := json.Unmarshal(raw, &rl); err != nil {
		return nil
	}
	return &rl
}

// parseWafLogging decodes a rule's logging block into whether matches are
// recorded. It returns nil when the rule carries no logging block, so a rule
// whose logging is simply not configurable is not reported as one that logs
// nothing.
func parseWafLogging(raw json.RawMessage) *bool {
	if len(raw) == 0 {
		return nil
	}
	var logging struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &logging); err != nil {
		return nil
	}
	return logging.Enabled
}

// skipRulesDict converts a skip rule's ruleset-to-rules map into a dict-safe
// value, returning null when the rule is not a skip rule.
func skipRulesDict(m map[string][]string) *llx.RawData {
	if m == nil {
		return llx.NilData
	}
	out := make(map[string]any, len(m))
	for rulesetID, ruleIDs := range m {
		out[rulesetID] = convert.SliceAnyToInterface(ruleIDs)
	}
	return llx.DictData(out)
}

// wafRules expands every ruleset attached to the zone (managed and custom)
// into the individual rules that make it up. We surface ruleset metadata on
// each rule so downstream queries can distinguish managed-by-Cloudflare rules
// from zone-defined custom rules. Empty rulesets and rate-limit/transform
// phases are kept — callers can filter by `rulesetPhase` or `rulesetKind`.
func (c *mqlCloudflareZone) wafRules() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.Rulesets.ListAutoPaging(context.TODO(), rulesets.RulesetListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		rs := iter.Current()

		// The list only returns ruleset metadata; fetch each ruleset to get its
		// rules. Skip individual rulesets that the caller can't read (e.g.,
		// managed rulesets requiring extra entitlements) but surface
		// transient/unknown errors so they aren't silently swallowed.
		var full rulesetDetail
		uri := fmt.Sprintf("zones/%s/rulesets/%s", c.Id.Data, rs.ID)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &full); err != nil {
			if isUnavailable(err) {
				continue
			}
			return nil, err
		}

		for j := range full.Result.Rules {
			r := full.Result.Rules[j]

			ruleVersion := full.Result.Version
			if r.Version != "" {
				ruleVersion = r.Version
			}

			ruleKey := c.Id.Data + "/" + rs.ID + "/" + r.ID
			params := parseWafActionParameters(r.ActionParameters)

			ruleOverrides, err := c.wafRuleOverrideResources(ruleKey, params.RuleOverrides)
			if err != nil {
				return nil, err
			}
			categoryOverrides, err := c.wafCategoryOverrideResources(ruleKey, params.CategoryOverrides)
			if err != nil {
				return nil, err
			}

			rl := parseWafRatelimit(r.Ratelimit)
			var (
				rlCharacteristics   = llx.NilData
				rlPeriod            = llx.NilData
				rlRequestsPerPeriod = llx.NilData
				rlMitigationTimeout = llx.NilData
				rlCountingExpr      = llx.NilData
				rlRequestsToOrigin  = llx.NilData
			)
			if rl != nil {
				rlCharacteristics = llx.ArrayData(convert.SliceAnyToInterface(rl.Characteristics), types.String)
				rlPeriod = llx.IntDataPtr(rl.Period)
				rlRequestsPerPeriod = llx.IntDataPtr(rl.RequestsPerPeriod)
				rlMitigationTimeout = llx.IntDataPtr(rl.MitigationTimeout)
				rlCountingExpr = llx.StringData(rl.CountingExpression)
				rlRequestsToOrigin = llx.BoolDataPtr(rl.RequestsToOrigin)
			}

			res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.wafRule", map[string]*llx.RawData{
				"__id":           llx.StringData("cloudflare.zone.wafRule@" + ruleKey),
				"id":             llx.StringData(r.ID),
				"rulesetId":      llx.StringData(rs.ID),
				"rulesetName":    llx.StringData(rs.Name),
				"rulesetKind":    llx.StringData(string(rs.Kind)),
				"rulesetPhase":   llx.StringData(string(rs.Phase)),
				"action":         llx.StringData(r.Action),
				"expression":     llx.StringData(r.Expression),
				"description":    llx.StringData(r.Description),
				"ref":            llx.StringData(r.Ref),
				"enabled":        llx.BoolData(r.Enabled),
				"scoreThreshold": llx.IntData(r.ScoreThreshold),
				"version":        llx.StringData(ruleVersion),
				"lastUpdated":    timeOrNil(r.LastUpdated),

				"loggingEnabled":           llx.BoolDataPtr(parseWafLogging(r.Logging)),
				"overrideAction":           llx.StringData(params.OverrideAction),
				"overrideEnabled":          llx.BoolDataPtr(params.OverrideEnabled),
				"overrideSensitivityLevel": llx.StringData(params.OverrideSensitivityLevel),
				"overriddenRules":          llx.ArrayData(ruleOverrides, types.Resource("cloudflare.zone.wafRule.override")),
				"overriddenCategories":     llx.ArrayData(categoryOverrides, types.Resource("cloudflare.zone.wafRule.categoryOverride")),

				"skipPhases":   llx.ArrayData(convert.SliceAnyToInterface(params.SkipPhases), types.String),
				"skipProducts": llx.ArrayData(convert.SliceAnyToInterface(params.SkipProducts), types.String),
				"skipRulesets": llx.ArrayData(convert.SliceAnyToInterface(params.SkipRulesets), types.String),
				"skipRules":    skipRulesDict(params.SkipRules),

				"rateLimitCharacteristics":    rlCharacteristics,
				"rateLimitPeriod":             rlPeriod,
				"rateLimitRequestsPerPeriod":  rlRequestsPerPeriod,
				"rateLimitMitigationTimeout":  rlMitigationTimeout,
				"rateLimitCountingExpression": rlCountingExpr,
				"rateLimitRequestsToOrigin":   rlRequestsToOrigin,
			})
			if err != nil {
				return nil, err
			}

			result = append(result, res)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// wafRuleOverrideResources builds the per-rule override resources for one
// ruleset rule. ruleKey scopes the cache key to the deploying rule, because the
// same managed rule id can be overridden differently by two deployments.
func (c *mqlCloudflareZone) wafRuleOverrideResources(ruleKey string, overrides []wafRuleOverride) ([]any, error) {
	result := make([]any, 0, len(overrides))
	for i := range overrides {
		o := overrides[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.wafRule.override", map[string]*llx.RawData{
			"__id":              llx.StringData("cloudflare.zone.wafRule.override@" + ruleKey + "/" + o.ID),
			"ruleId":            llx.StringData(o.ID),
			"action":            llx.StringData(o.Action),
			"enabled":           llx.BoolDataPtr(o.Enabled),
			"scoreThreshold":    llx.IntDataPtr(o.ScoreThreshold),
			"sensitivityLevel":  llx.StringData(o.SensitivityLevel),
			"sensitivityStatus": llx.StringData(o.Status),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

// wafCategoryOverrideResources builds the per-category override resources for
// one ruleset rule.
func (c *mqlCloudflareZone) wafCategoryOverrideResources(ruleKey string, overrides []wafCategoryOverride) ([]any, error) {
	result := make([]any, 0, len(overrides))
	for i := range overrides {
		o := overrides[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.wafRule.categoryOverride", map[string]*llx.RawData{
			"__id":     llx.StringData("cloudflare.zone.wafRule.categoryOverride@" + ruleKey + "/" + o.Category),
			"category": llx.StringData(o.Category),
			"action":   llx.StringData(o.Action),
			"enabled":  llx.BoolDataPtr(o.Enabled),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}
