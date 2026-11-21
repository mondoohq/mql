// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/page_rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulesets(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/rulesets", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("rulesets"))
	})

	result, err := zone.rulesets()
	require.NoError(t, err)
	require.Len(t, result, 2)

	rs := result[0].(*mqlCloudflareZoneRuleset)
	assert.Equal(t, "rs-managed-1", rs.Id.Data)
	assert.Equal(t, "Cloudflare Managed Ruleset", rs.Name.Data)
	assert.Equal(t, "managed", rs.Kind.Data)
	assert.Equal(t, "http_request_firewall_managed", rs.Phase.Data)
	assert.Equal(t, "3", rs.Version.Data)

	rs2 := result[1].(*mqlCloudflareZoneRuleset)
	assert.Equal(t, "Custom WAF Rules", rs2.Name.Data)
	assert.Equal(t, "zone", rs2.Kind.Data)
}

func TestPageRules(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/pagerules", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("page_rules"))
	})

	result, err := zone.pageRules()
	require.NoError(t, err)
	require.Len(t, result, 1)

	pr := result[0].(*mqlCloudflareZonePageRule)
	assert.Equal(t, "pr-001", pr.Id.Data)
	assert.Equal(t, "active", pr.Status.Data)
	assert.Equal(t, int64(1), pr.Priority.Data)
	assert.False(t, pr.CreatedAt.Data.IsZero())
	assert.Equal(t, []any{"*example.com/images/*"}, pr.Targets.Data)
	assert.Equal(t, []any{
		map[string]any{"id": "always_use_https", "value": nil},
		map[string]any{"id": "ssl", "value": "flexible"},
		map[string]any{"id": "forwarding_url", "value": map[string]any{
			"url":         "https://www.example.com/$1",
			"status_code": float64(301),
		}},
	}, pr.Actions.Data)
}

func TestPageRuleMapping(t *testing.T) {
	var rule page_rules.PageRule
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "pr-002",
		"targets": [
			{"target": "url", "constraint": {"operator": "matches", "value": "example.com/a/*"}},
			{"target": "url", "constraint": {"operator": "matches", "value": "example.com/b/*"}}
		],
		"actions": [
			{"id": "cache_level", "value": "bypass"},
			{"id": "edge_cache_ttl", "value": 7200}
		]
	}`), &rule))

	assert.Equal(t, []any{"example.com/a/*", "example.com/b/*"}, pageRuleTargets(rule.Targets))
	assert.Equal(t, []any{
		map[string]any{"id": "cache_level", "value": "bypass"},
		map[string]any{"id": "edge_cache_ttl", "value": float64(7200)},
	}, pageRuleActions(rule.Actions))

	assert.Equal(t, []any{}, pageRuleTargets(nil))
	assert.Equal(t, []any{}, pageRuleActions(nil))
}
