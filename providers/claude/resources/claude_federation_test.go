// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountArgs(t *testing.T) {
	var sa anthropic.BetaServiceAccount
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "svac_0000",
		"type": "service_account",
		"name": "ci-deployer",
		"description": "runs deployments",
		"organization_role": "admin",
		"created_at": "2026-03-01T10:00:00Z",
		"updated_at": "2026-04-01T10:00:00Z",
		"created_by_actor_id": "user_0001"
	}`), &sa))

	args := serviceAccountArgs(sa)
	assert.Equal(t, "svac_0000", args["id"].Value)
	assert.Equal(t, "ci-deployer", args["name"].Value)
	// An admin service account administers the organization with no person
	// involved, so this value is the point of the resource.
	assert.Equal(t, "admin", args["organizationRole"].Value)
	assert.Equal(t, "user_0001", args["createdByActorId"].Value)
}

// A live service account has no archive timestamp and no archiving actor.
// Reporting the zero time would date the archival to year 1, making every
// active account look long retired.
func TestServiceAccountArgsActiveAccountReadsNull(t *testing.T) {
	var sa anthropic.BetaServiceAccount
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "svac_0001",
		"type": "service_account",
		"name": "live",
		"organization_role": "developer",
		"created_at": "2026-03-01T10:00:00Z",
		"created_by_actor_id": "user_0001"
	}`), &sa))

	args := serviceAccountArgs(sa)
	assert.Nil(t, args["archivedAt"].Value)
	assert.Nil(t, args["archivedByActorId"].Value)
	assert.Nil(t, args["updatedByActorId"].Value)
}

func TestFederationIssuerArgs(t *testing.T) {
	var iss anthropic.BetaFederationIssuer
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "fediss_0000",
		"type": "federation_issuer",
		"name": "github-actions",
		"issuer_url": "https://token.actions.githubusercontent.com",
		"check_jti": true,
		"max_jwt_lifetime_seconds": 900,
		"created_at": "2026-03-01T10:00:00Z",
		"created_by_actor_id": "user_0001",
		"poll_status": {"status": "ok"}
	}`), &iss))

	args, err := federationIssuerArgs(iss)
	require.NoError(t, err)

	assert.Equal(t, "https://token.actions.githubusercontent.com", args["issuerUrl"].Value,
		"the issuer URL names whose tokens are trusted and is the whole trust decision")
	assert.Equal(t, true, args["checkJti"].Value)
	assert.Equal(t, int64(900), args["maxJwtLifetimeSeconds"].Value)
	assert.Nil(t, args["jwksPollingDisabledAt"].Value)

	poll, ok := args["pollStatus"].Value.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ok", poll["status"])
}

// An issuer whose nested objects the API omitted must read as null rather than
// as an empty object, so "we did not get a poll status" stays distinct from
// "the poll status came back empty".
func TestFederationIssuerArgsAbsentNestedObjectsReadNull(t *testing.T) {
	var iss anthropic.BetaFederationIssuer
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "fediss_0001",
		"type": "federation_issuer",
		"name": "minimal",
		"issuer_url": "https://issuer.example.com",
		"created_at": "2026-03-01T10:00:00Z",
		"created_by_actor_id": "user_0001"
	}`), &iss))

	args, err := federationIssuerArgs(iss)
	require.NoError(t, err)
	assert.Nil(t, args["pollStatus"].Value)
	assert.Nil(t, args["jwks"].Value)
}

func TestFederationRuleArgs(t *testing.T) {
	var rule anthropic.BetaFederationRule
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "fedrule_0000",
		"type": "federation_rule",
		"name": "prod-deploy",
		"description": "deploys from the release workflow",
		"issuer_id": "fediss_0000",
		"applies_to_all_workspaces": false,
		"oauth_scope": "user:inference",
		"token_lifetime_seconds": 3600,
		"created_at": "2026-03-01T10:00:00Z",
		"created_by_actor_id": "user_0001",
		"match": {
			"audience": "https://api.anthropic.com",
			"subject_prefix": "repo:acme/app:ref:refs/heads/main",
			"claims": {"repository_owner": "acme"},
			"condition": "claims.environment == 'production'"
		}
	}`), &rule))

	args, err := federationRuleArgs(rule)
	require.NoError(t, err)

	// These four together decide how narrowly the rule matches, which is what
	// separates a scoped grant from a standing one.
	assert.Equal(t, "https://api.anthropic.com", args["matchAudience"].Value)
	assert.Equal(t, "repo:acme/app:ref:refs/heads/main", args["matchSubjectPrefix"].Value)
	assert.Equal(t, map[string]any{"repository_owner": "acme"}, args["matchClaims"].Value)
	assert.Equal(t, "claims.environment == 'production'", args["matchCondition"].Value)

	assert.Equal(t, false, args["appliesToAllWorkspaces"].Value)
	assert.Equal(t, int64(3600), args["tokenLifetimeSeconds"].Value)
}

// A rule that constrains nothing must report null for each unset matcher, not
// "". An empty string reads as a configured constraint that happens to be
// blank, which hides exactly the rule an audit is looking for.
func TestFederationRuleArgsUnconstrainedMatchersReadNull(t *testing.T) {
	var rule anthropic.BetaFederationRule
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "fedrule_0001",
		"type": "federation_rule",
		"name": "wide-open",
		"issuer_id": "fediss_0000",
		"applies_to_all_workspaces": true,
		"created_at": "2026-03-01T10:00:00Z",
		"created_by_actor_id": "user_0001",
		"match": {}
	}`), &rule))

	args, err := federationRuleArgs(rule)
	require.NoError(t, err)
	assert.Nil(t, args["matchAudience"].Value)
	assert.Nil(t, args["matchSubjectPrefix"].Value)
	assert.Nil(t, args["matchCondition"].Value)
	assert.Equal(t, true, args["appliesToAllWorkspaces"].Value)
}

// The API reports a rule's workspaces on either the singular workspace_id or
// the plural workspace_ids. Reading only one of them under-reports how far the
// rule reaches, and reading both naively double-counts the overlap.
func TestFederationRuleWorkspaceIDsMergesBothShapes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []string
	}{
		{"singular only", `{"workspace_id": "wrkspc_a"}`, []string{"wrkspc_a"}},
		{"plural only", `{"workspace_ids": ["wrkspc_a", "wrkspc_b"]}`, []string{"wrkspc_a", "wrkspc_b"}},
		{"both, overlapping", `{"workspace_id": "wrkspc_a", "workspace_ids": ["wrkspc_a", "wrkspc_b"]}`, []string{"wrkspc_a", "wrkspc_b"}},
		{"neither", `{}`, []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rule anthropic.BetaFederationRule
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &rule))
			assert.Equal(t, tc.want, federationRuleWorkspaceIDs(rule))
		})
	}
}

func TestNullableTimeAndString(t *testing.T) {
	assert.Nil(t, nullableTime(time.Time{}))
	assert.Nil(t, nullableString(""))

	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	require.NotNil(t, nullableTime(now))
	assert.Equal(t, now, *nullableTime(now))

	require.NotNil(t, nullableString("x"))
	assert.Equal(t, "x", *nullableString("x"))
}
