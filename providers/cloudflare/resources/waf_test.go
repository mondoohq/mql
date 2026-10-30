// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWafRules(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("rulesets"))
	})

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets/rs-managed-1", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("waf_ruleset_managed"))
	})

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets/rs-custom-1", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("waf_ruleset_custom"))
	})

	result, err := zone.wafRules()
	require.NoError(t, err)
	require.Len(t, result, 3, "expected 2 rules from managed ruleset + 1 from custom")

	// First rule: high-threat block from managed ruleset
	r1 := result[0].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, "rule-mgd-001", r1.Id.Data)
	assert.Equal(t, "rs-managed-1", r1.RulesetId.Data)
	assert.Equal(t, "Cloudflare Managed Ruleset", r1.RulesetName.Data)
	assert.Equal(t, "managed", r1.RulesetKind.Data)
	assert.Equal(t, "http_request_firewall_managed", r1.RulesetPhase.Data)
	assert.Equal(t, "block", r1.Action.Data)
	assert.Equal(t, "cf.threat_score gt 50", r1.Expression.Data)
	assert.True(t, r1.Enabled.Data)
	assert.Equal(t, int64(50), r1.ScoreThreshold.Data)
	assert.Equal(t, "3", r1.Version.Data)

	// Second rule: disabled challenge from managed ruleset
	r2 := result[1].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, "rule-mgd-002", r2.Id.Data)
	assert.Equal(t, "challenge", r2.Action.Data)
	assert.False(t, r2.Enabled.Data, "rule with enabled=false should preserve that")

	// Third rule: zone-defined custom rule
	r3 := result[2].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, "rule-custom-001", r3.Id.Data)
	assert.Equal(t, "rs-custom-1", r3.RulesetId.Data)
	assert.Equal(t, "zone", r3.RulesetKind.Data)
	assert.Equal(t, "block", r3.Action.Data)
	assert.True(t, r3.Enabled.Data)
}

func TestWafRules_skipsForbiddenRulesets(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("rulesets"))
	})

	// Managed ruleset returns 403 — should be skipped, not failed
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets/rs-managed-1", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Insufficient permissions"}]}`)
	})

	// Custom ruleset succeeds
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets/rs-custom-1", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("waf_ruleset_custom"))
	})

	result, err := zone.wafRules()
	require.NoError(t, err)
	require.Len(t, result, 1, "should keep going past forbidden managed ruleset")
	r := result[0].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, "rule-custom-001", r.Id.Data)
}

func TestParseWafActionParameters(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		verify func(t *testing.T, got wafActionParameters)
	}{
		{
			name: "absent action_parameters",
			raw:  "",
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Equal(t, wafActionParameters{}, got)
			},
		},
		{
			name: "managed ruleset switched off by an override",
			raw: `{"id":"managed-1","overrides":{"action":"log","enabled":false,` +
				`"sensitivity_level":"low",` +
				`"categories":[{"category":"wordpress","action":"block","enabled":true}],` +
				`"rules":[{"id":"r1","action":"log","enabled":false,"score_threshold":60,` +
				`"sensitivity_level":"eoff","status":"disabled"}]}}`,
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Equal(t, "log", got.OverrideAction)
				require.NotNil(t, got.OverrideEnabled)
				assert.False(t, *got.OverrideEnabled, "enabled:false must not be lost")
				assert.Equal(t, "low", got.OverrideSensitivityLevel)

				require.Len(t, got.CategoryOverrides, 1)
				assert.Equal(t, "wordpress", got.CategoryOverrides[0].Category)
				require.NotNil(t, got.CategoryOverrides[0].Enabled)
				assert.True(t, *got.CategoryOverrides[0].Enabled)

				require.Len(t, got.RuleOverrides, 1)
				ro := got.RuleOverrides[0]
				assert.Equal(t, "r1", ro.ID)
				assert.Equal(t, "log", ro.Action)
				require.NotNil(t, ro.Enabled)
				assert.False(t, *ro.Enabled)
				require.NotNil(t, ro.ScoreThreshold)
				assert.Equal(t, int64(60), *ro.ScoreThreshold)
				assert.Equal(t, "eoff", ro.SensitivityLevel)
				assert.Equal(t, "disabled", ro.Status)
			},
		},
		{
			name: "override that omits enabled leaves it null",
			raw:  `{"overrides":{"action":"block","rules":[{"id":"r1","action":"block"}]}}`,
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Nil(t, got.OverrideEnabled, "an absent enabled must stay null, not become false")
				require.Len(t, got.RuleOverrides, 1)
				assert.Nil(t, got.RuleOverrides[0].Enabled)
				assert.Nil(t, got.RuleOverrides[0].ScoreThreshold)
			},
		},
		{
			name: "skip rule bypassing phases, products and rules",
			raw: `{"phases":["http_ratelimit"],"products":["waf","zoneLockdown"],` +
				`"rulesets":["managed-1"],"rules":{"managed-1":["r1","r2"]}}`,
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Equal(t, []string{"http_ratelimit"}, got.SkipPhases)
				assert.Equal(t, []string{"waf", "zoneLockdown"}, got.SkipProducts)
				assert.Equal(t, []string{"managed-1"}, got.SkipRulesets)
				assert.Equal(t, map[string][]string{"managed-1": {"r1", "r2"}}, got.SkipRules)
			},
		},
		{
			name: "unrelated action_parameters shape yields nothing, not an error",
			raw:  `{"response":{"content":"blocked","status_code":403}}`,
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Equal(t, wafActionParameters{}, got)
			},
		},
		{
			name: "rules key with an unexpected shape leaves skipRules null",
			raw:  `{"rules":["r1","r2"]}`,
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Nil(t, got.SkipRules)
			},
		},
		{
			name: "malformed json yields a zero value",
			raw:  `{"overrides":`,
			verify: func(t *testing.T, got wafActionParameters) {
				assert.Equal(t, wafActionParameters{}, got)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.verify(t, parseWafActionParameters(json.RawMessage(tc.raw)))
		})
	}
}

func TestParseWafRatelimit(t *testing.T) {
	t.Run("absent block is null", func(t *testing.T) {
		assert.Nil(t, parseWafRatelimit(nil))
	})

	t.Run("thresholds are preserved", func(t *testing.T) {
		rl := parseWafRatelimit(json.RawMessage(`{"characteristics":["ip.src"],"period":60,` +
			`"requests_per_period":100,"mitigation_timeout":600,` +
			`"counting_expression":"http.response.code eq 401","requests_to_origin":true}`))
		require.NotNil(t, rl)
		assert.Equal(t, []string{"ip.src"}, rl.Characteristics)
		require.NotNil(t, rl.Period)
		assert.Equal(t, int64(60), *rl.Period)
		require.NotNil(t, rl.RequestsPerPeriod)
		assert.Equal(t, int64(100), *rl.RequestsPerPeriod)
		require.NotNil(t, rl.MitigationTimeout)
		assert.Equal(t, int64(600), *rl.MitigationTimeout)
		assert.Equal(t, "http.response.code eq 401", rl.CountingExpression)
		require.NotNil(t, rl.RequestsToOrigin)
		assert.True(t, *rl.RequestsToOrigin)
	})

	t.Run("omitted numbers stay null rather than zero", func(t *testing.T) {
		rl := parseWafRatelimit(json.RawMessage(`{"characteristics":["ip.src"]}`))
		require.NotNil(t, rl)
		assert.Nil(t, rl.RequestsPerPeriod, "a null threshold must not read as a limit of zero requests")
		assert.Nil(t, rl.Period)
		assert.Nil(t, rl.MitigationTimeout)
	})

	t.Run("malformed json is null", func(t *testing.T) {
		assert.Nil(t, parseWafRatelimit(json.RawMessage(`{"period":`)))
	})
}

func TestParseWafLogging(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want *bool
	}{
		{"absent block is null", "", nil},
		{"logging on", `{"enabled":true}`, new(true)},
		{"logging off", `{"enabled":false}`, new(false)},
		{"block present but enabled omitted is null", `{}`, nil},
		{"malformed json is null", `{"enabled":`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWafLogging(json.RawMessage(tc.raw))
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

func TestWafRules_enforcementParameters(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("rulesets_enforcement"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets/rs-enforcement-1", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("waf_ruleset_enforcement"))
	})

	result, err := zone.wafRules()
	require.NoError(t, err)
	require.Len(t, result, 4)

	// An execute rule that deploys a managed ruleset but disables it wholesale.
	exec := result[0].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, "rule-exec-001", exec.Id.Data)
	assert.True(t, exec.Enabled.Data, "the deploying rule itself reads enabled")
	assert.Equal(t, "log", exec.OverrideAction.Data)
	assert.False(t, exec.OverrideEnabled.Data, "the managed ruleset it deploys is switched off")
	assert.Equal(t, "low", exec.OverrideSensitivityLevel.Data)
	assert.False(t, exec.LoggingEnabled.Data)

	require.Len(t, exec.OverriddenRules.Data, 2)
	ro := exec.OverriddenRules.Data[0].(*mqlCloudflareZoneWafRuleOverride)
	assert.Equal(t, "5de7edfa648c4d6891dc3e7f84534ffa", ro.RuleId.Data)
	assert.Equal(t, "log", ro.Action.Data)
	assert.False(t, ro.Enabled.Data)
	assert.Equal(t, int64(60), ro.ScoreThreshold.Data)
	assert.Equal(t, "eoff", ro.SensitivityLevel.Data)
	assert.Equal(t, "disabled", ro.SensitivityStatus.Data)

	// The second override omits enabled and score_threshold entirely.
	ro2 := exec.OverriddenRules.Data[1].(*mqlCloudflareZoneWafRuleOverride)
	assert.Equal(t, "e3a567afc347477d9702d9047e97d760", ro2.RuleId.Data)
	assert.True(t, ro2.Enabled.IsNull(), "an override that does not touch enabled must read null")
	assert.True(t, ro2.ScoreThreshold.IsNull())

	require.Len(t, exec.OverriddenCategories.Data, 2)
	co := exec.OverriddenCategories.Data[0].(*mqlCloudflareZoneWafRuleCategoryOverride)
	assert.Equal(t, "wordpress", co.Category.Data)
	assert.Equal(t, "block", co.Action.Data)
	assert.True(t, co.Enabled.Data)

	// Distinct cache keys, or the second override would alias the first.
	assert.NotEqual(t, ro.__id, ro2.__id)

	// A skip rule that takes matching traffic out of the WAF entirely.
	skip := result[1].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, "skip", skip.Action.Data)
	assert.Equal(t, []any{"http_ratelimit", "http_request_firewall_managed"}, skip.SkipPhases.Data)
	assert.Equal(t, []any{"waf", "rateLimit", "zoneLockdown"}, skip.SkipProducts.Data)
	assert.Equal(t, []any{"efb7b8c949ac4650a09736fc376e9aee"}, skip.SkipRulesets.Data)
	assert.Equal(t, map[string]any{
		"efb7b8c949ac4650a09736fc376e9aee": []any{"5de7edfa648c4d6891dc3e7f84534ffa"},
	}, skip.SkipRules.Data)
	assert.True(t, skip.LoggingEnabled.Data)

	// A rate-limit rule and its thresholds.
	rl := result[2].(*mqlCloudflareZoneWafRule)
	assert.Equal(t, int64(100), rl.RateLimitRequestsPerPeriod.Data)
	assert.Equal(t, int64(60), rl.RateLimitPeriod.Data)
	assert.Equal(t, int64(600), rl.RateLimitMitigationTimeout.Data)
	assert.Equal(t, []any{"cf.colo.id", "ip.src"}, rl.RateLimitCharacteristics.Data)
	assert.Equal(t, "http.response.code eq 401", rl.RateLimitCountingExpression.Data)
	assert.True(t, rl.RateLimitRequestsToOrigin.Data)

	// A plain block rule carries none of it, and must report null rather than
	// a threshold of zero or an override that was never configured.
	plain := result[3].(*mqlCloudflareZoneWafRule)
	assert.True(t, plain.RateLimitRequestsPerPeriod.IsNull())
	assert.True(t, plain.RateLimitPeriod.IsNull())
	assert.True(t, plain.RateLimitCharacteristics.IsNull())
	assert.True(t, plain.RateLimitRequestsToOrigin.IsNull())
	assert.True(t, plain.OverrideEnabled.IsNull())
	assert.True(t, plain.LoggingEnabled.IsNull())
	assert.True(t, plain.SkipRules.IsNull())
	assert.Empty(t, plain.SkipProducts.Data)
	assert.Empty(t, plain.OverriddenRules.Data)
}
