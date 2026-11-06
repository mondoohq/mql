// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// firstPageOnly serves body on the first page and an empty result after it,
// which is what stops the SDK's page-number auto pager.
func firstPageOnly(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"success": true, "errors": [], "messages": [], "result": []}`)
			return
		}
		jsonResponse(w, body)
	}
}

// Synthetic: both DLP shapes the API documents (one action for a profile list,
// and per-policy actions), guardrails, spend limits, and nullable limits sent
// as null. No test account had a configured gateway.
const aiGatewaysBody = `{
	"success": true, "errors": [], "messages": [],
	"result": [
		{
			"id": "legacy-dlp",
			"authentication": false,
			"byok_only": true,
			"is_default": true,
			"collect_logs": true,
			"logpush": false,
			"log_management": 10000,
			"log_management_strategy": "DELETE_OLDEST",
			"zdr": true,
			"fedramp_level": null,
			"cache_ttl": null,
			"cache_invalidate_on_update": false,
			"rate_limiting_limit": 0,
			"rate_limiting_interval": null,
			"rate_limiting_technique": null,
			"dlp": {"enabled": true, "action": "BLOCK", "profiles": ["prof-1", "prof-missing"]},
			"guardrails": {
				"prompt": {"S1": "BLOCK", "P1": "FLAG"},
				"response": {}
			},
			"otel": [{"url": "https://otel.example.com", "headers": {"x-api-key": "hidden"}, "authorization": "Bearer hidden"}],
			"created_at": "2026-01-02T03:04:05Z",
			"modified_at": "2026-02-03T04:05:06Z"
		},
		{
			"id": "policy-dlp",
			"authentication": true,
			"collect_logs": false,
			"cache_ttl": 300,
			"rate_limiting_limit": 50,
			"rate_limiting_interval": 60,
			"rate_limiting_technique": "sliding",
			"dlp": {"enabled": true, "policies": [
				{"id": "pol-1", "enabled": true, "action": "FLAG", "check": ["REQUEST", "RESPONSE"], "profiles": ["prof-2", "prof-1"]}
			]},
			"spend_limits": {"enabled": true, "rules": [
				{"id": "rule-1", "enabled": true, "limit": 12.5, "limitType": "cost", "window": 86400, "technique": "fixed",
				 "model": {"mode": "filter", "values": ["gpt-4o"]},
				 "metadata": {"team": {"mode": "partition"}}},
				{"enabled": false, "limit": 100, "limitType": "cost", "window": 3600}
			]},
			"created_at": "2026-01-02T03:04:05Z",
			"modified_at": "2026-01-02T03:04:05Z"
		}
	],
	"result_info": {"page": 1, "per_page": 20, "count": 2, "total_count": 2}
}`

const dlpProfilesBody = `{
	"success": true, "errors": [], "messages": [],
	"result": [
		{"id": "prof-1", "name": "Credit cards", "type": "predefined"},
		{"id": "prof-2", "name": "Source code", "type": "custom"}
	]
}`

func loadTestAIGateways(t *testing.T, env *testEnv) map[string]*mqlCloudflareAccountAiGateway {
	t.Helper()
	acc := createTestAccount(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/ai-gateway/gateways", testAccountID), firstPageOnly(aiGatewaysBody))

	result, err := acc.aiGateways()
	require.NoError(t, err)
	require.Len(t, result, 2)

	byID := map[string]*mqlCloudflareAccountAiGateway{}
	for _, r := range result {
		g := r.(*mqlCloudflareAccountAiGateway)
		byID[g.Id.Data] = g
	}
	return byID
}

func TestAIGatewaysDecode(t *testing.T) {
	env := setupTestEnv(t)
	gws := loadTestAIGateways(t, env)

	legacy := gws["legacy-dlp"]
	require.NotNil(t, legacy)
	assert.False(t, legacy.Authentication.Data)
	assert.True(t, legacy.ByokOnly.Data)
	assert.True(t, legacy.IsDefault.Data)
	assert.True(t, legacy.CollectLogs.Data)
	assert.Equal(t, int64(10000), legacy.LogManagement.Data)
	assert.Equal(t, "DELETE_OLDEST", legacy.LogManagementStrategy.Data)
	assert.True(t, legacy.ZeroDataRetention.Data)
	assert.True(t, legacy.DlpEnabled.Data)
	assert.Equal(t, "BLOCK", legacy.DlpAction.Data)
	assert.Equal(t, map[string]any{"S1": "BLOCK", "P1": "FLAG"}, legacy.PromptGuardrails.Data)
	assert.Equal(t, map[string]any{}, legacy.ResponseGuardrails.Data)
	assert.False(t, legacy.SpendLimitsEnabled.Data)
	assert.Equal(t, "2026-01-02T03:04:05Z", legacy.CreatedAt.Data.UTC().Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, "2026-02-03T04:05:06Z", legacy.ModifiedAt.Data.UTC().Format("2006-01-02T15:04:05Z"))

	// null limits stay null; an explicit 0 stays 0.
	assert.True(t, legacy.CacheTtl.IsNull())
	assert.True(t, legacy.FedrampLevel.IsNull())
	assert.True(t, legacy.RateLimitingInterval.IsNull())
	assert.True(t, legacy.RateLimitingTechnique.IsNull())
	assert.False(t, legacy.RateLimitingLimit.IsNull())
	assert.Equal(t, int64(0), legacy.RateLimitingLimit.Data)

	policy := gws["policy-dlp"]
	require.NotNil(t, policy)
	assert.True(t, policy.Authentication.Data)
	assert.Equal(t, int64(300), policy.CacheTtl.Data)
	assert.Equal(t, int64(50), policy.RateLimitingLimit.Data)
	assert.Equal(t, int64(60), policy.RateLimitingInterval.Data)
	assert.Equal(t, "sliding", policy.RateLimitingTechnique.Data)
	assert.True(t, policy.DlpEnabled.Data)
	// The per-policy shape has no gateway-wide action.
	assert.True(t, policy.DlpAction.IsNull())
	// Absent fields: null, not an empty map or a default.
	assert.True(t, policy.PromptGuardrails.IsNull())
	assert.True(t, policy.ResponseGuardrails.IsNull())
	assert.True(t, policy.LogManagement.IsNull())
	assert.True(t, policy.LogManagementStrategy.IsNull())
	assert.True(t, policy.SpendLimitsEnabled.Data)
}

func TestAIGatewayDLP(t *testing.T) {
	env := setupTestEnv(t)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/dlp/profiles", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, dlpProfilesBody)
	})
	gws := loadTestAIGateways(t, env)

	// Profiles shape: the profile the account no longer has is dropped.
	profiles, err := gws["legacy-dlp"].dlpProfiles()
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	assert.Equal(t, "Credit cards", profiles[0].(*mqlCloudflareOneDlpProfile).Name.Data)

	none, err := gws["legacy-dlp"].dlpPolicies()
	require.NoError(t, err)
	assert.Empty(t, none)

	// Policies shape.
	none, err = gws["policy-dlp"].dlpProfiles()
	require.NoError(t, err)
	assert.Empty(t, none)

	policies, err := gws["policy-dlp"].dlpPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	p := policies[0].(*mqlCloudflareAccountAiGatewayDlpPolicy)
	assert.Equal(t, "pol-1", p.Id.Data)
	assert.True(t, p.Enabled.Data)
	assert.Equal(t, "FLAG", p.Action.Data)
	assert.Equal(t, []any{"REQUEST", "RESPONSE"}, p.Check.Data)

	pp, err := p.profiles()
	require.NoError(t, err)
	require.Len(t, pp, 2)
	// Order follows the policy, not the account listing.
	assert.Equal(t, "prof-2", pp[0].(*mqlCloudflareOneDlpProfile).Id.Data)
	assert.Equal(t, "prof-1", pp[1].(*mqlCloudflareOneDlpProfile).Id.Data)
}

func TestAIGatewaySpendLimitRules(t *testing.T) {
	env := setupTestEnv(t)
	gws := loadTestAIGateways(t, env)

	none, err := gws["legacy-dlp"].spendLimitRules()
	require.NoError(t, err)
	assert.Empty(t, none)

	rules, err := gws["policy-dlp"].spendLimitRules()
	require.NoError(t, err)
	require.Len(t, rules, 2)

	r1 := rules[0].(*mqlCloudflareAccountAiGatewaySpendLimitRule)
	assert.Equal(t, "rule-1", r1.Id.Data)
	assert.True(t, r1.Enabled.Data)
	assert.Equal(t, 12.5, r1.Limit.Data)
	assert.Equal(t, "cost", r1.LimitType.Data)
	assert.Equal(t, int64(86400), r1.Window.Data)
	assert.Equal(t, "fixed", r1.Technique.Data)
	assert.Equal(t, []any{"gpt-4o"}, r1.Models.Data)
	assert.Equal(t, []any{}, r1.Providers.Data)
	assert.Equal(t, map[string]any{"team": map[string]any{"mode": "partition"}}, r1.Metadata.Data)

	// A rule without an id must not collide with another id-less rule.
	r2 := rules[1].(*mqlCloudflareAccountAiGatewaySpendLimitRule)
	assert.False(t, r2.Enabled.Data)
	assert.Equal(t, 100.0, r2.Limit.Data)
	assert.Equal(t, int64(3600), r2.Window.Data)
	assert.NotEqual(t, r1.__id, r2.__id)
}

func TestAIGatewayProviderConfigs(t *testing.T) {
	env := setupTestEnv(t)
	gws := loadTestAIGateways(t, env)

	// Synthetic: one key used recently with a rate limit, one never used.
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/ai-gateway/gateways/policy-dlp/provider_configs", testAccountID), firstPageOnly(`{
		"success": true, "errors": [], "messages": [],
		"result": [
			{"id": "cfg-1", "alias": "prod", "default_config": true, "gateway_id": "policy-dlp",
			 "provider_slug": "openai", "secret_id": "sec-1", "secret_preview": "sk-...abcd",
			 "last_used_at": "2026-11-01", "rate_limit": 100, "rate_limit_period": 60,
			 "modified_at": "2026-10-01T00:00:00Z"},
			{"id": "cfg-2", "alias": "old", "default_config": false, "gateway_id": "policy-dlp",
			 "provider_slug": "anthropic", "secret_id": "sec-2", "secret_preview": "sk-...wxyz",
			 "last_used_at": null, "modified_at": "2025-01-01T00:00:00Z"}
		]
	}`))

	cfgs, err := gws["policy-dlp"].providerConfigs()
	require.NoError(t, err)
	require.Len(t, cfgs, 2)

	c1 := cfgs[0].(*mqlCloudflareAccountAiGatewayProviderConfig)
	assert.Equal(t, "cfg-1", c1.Id.Data)
	assert.Equal(t, "prod", c1.Alias.Data)
	assert.Equal(t, "openai", c1.ProviderSlug.Data)
	assert.True(t, c1.DefaultConfig.Data)
	assert.Equal(t, "sec-1", c1.SecretId.Data)
	assert.Equal(t, "2026-11-01", c1.LastUsedAt.Data.UTC().Format("2006-01-02"))
	assert.Equal(t, 100.0, c1.RateLimit.Data)
	assert.Equal(t, 60.0, c1.RateLimitPeriod.Data)

	c2 := cfgs[1].(*mqlCloudflareAccountAiGatewayProviderConfig)
	assert.Equal(t, "anthropic", c2.ProviderSlug.Data)
	assert.False(t, c2.DefaultConfig.Data)
	assert.True(t, c2.LastUsedAt.IsNull())
	assert.True(t, c2.RateLimit.IsNull())
	assert.True(t, c2.RateLimitPeriod.IsNull())
}

func TestAIGatewaysRefusal(t *testing.T) {
	t.Run("plan or product not available degrades to empty", func(t *testing.T) {
		env := setupTestEnv(t)
		acc := createTestAccount(t, env)
		env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/ai-gateway/gateways", testAccountID), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"success": false, "errors": [{"code": 10000, "message": "Authentication error"}], "messages": [], "result": null}`)
		})
		result, err := acc.aiGateways()
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("credential refusal surfaces", func(t *testing.T) {
		env := setupTestEnv(t)
		acc := createTestAccount(t, env)
		env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/ai-gateway/gateways", testAccountID), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"success": false, "errors": [{"code": 10002, "message": "Authorization Failure"}], "messages": [], "result": null}`)
		})
		_, err := acc.aiGateways()
		assert.Error(t, err)
	})
}

func TestHasNextAIGatewayPage(t *testing.T) {
	page := func(n, perPage, totalPages, totalCount int) aiGatewayPage {
		var p aiGatewayPage
		p.Result = make([]aiGatewayRecord, n)
		p.ResultInfo.PerPage = perPage
		p.ResultInfo.TotalPages = totalPages
		p.ResultInfo.TotalCount = totalCount
		return p
	}
	// Synthetic: each way the endpoint can report, or not report, the end.
	assert.False(t, hasNextAIGatewayPage(page(0, 50, 3, 120), 1, 0), "empty page ends the walk")
	assert.True(t, hasNextAIGatewayPage(page(50, 50, 3, 0), 2, 100))
	assert.False(t, hasNextAIGatewayPage(page(20, 50, 3, 0), 3, 120))
	assert.True(t, hasNextAIGatewayPage(page(20, 20, 0, 45), 1, 20), "server page smaller than requested")
	assert.False(t, hasNextAIGatewayPage(page(5, 20, 0, 45), 3, 45))
	assert.True(t, hasNextAIGatewayPage(page(50, 0, 0, 0), 1, 50), "no paging info, full page")
	assert.False(t, hasNextAIGatewayPage(page(7, 0, 0, 0), 1, 7), "no paging info, short page")
}

func TestAIGatewaysPagination(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	// Synthetic: 3 gateways served 2 per page with only a total count.
	var pages []string
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/ai-gateway/gateways", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		switch page {
		case "1":
			jsonResponse(w, `{"success": true, "result": [{"id": "a"}, {"id": "b"}], "result_info": {"page": 1, "per_page": 2, "total_count": 3}}`)
		case "2":
			jsonResponse(w, `{"success": true, "result": [{"id": "c"}], "result_info": {"page": 2, "per_page": 2, "total_count": 3}}`)
		default:
			t.Errorf("unexpected page %q", page)
			jsonResponse(w, `{"success": true, "result": []}`)
		}
	})

	result, err := acc.aiGateways()
	require.NoError(t, err)
	require.Len(t, result, 3)
	assert.Equal(t, "c", result[2].(*mqlCloudflareAccountAiGateway).Id.Data)
	assert.Equal(t, []string{"1", "2"}, pages)
}
