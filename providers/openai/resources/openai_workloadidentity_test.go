// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func decodeWorkloadIdentityProvider(t *testing.T, payload string) openai.WorkloadIdentityProvider {
	t.Helper()
	var p openai.WorkloadIdentityProvider
	require.NoError(t, json.Unmarshal([]byte(payload), &p))
	return p
}

func decodeFederationRule(t *testing.T, payload string) openai.FederationRule {
	t.Helper()
	var fr openai.FederationRule
	require.NoError(t, json.Unmarshal([]byte(payload), &fr))
	return fr
}

func TestWorkloadIdentityProviderArgsDiscovery(t *testing.T) {
	// Synthetic: discovery provider shaped after the SDK's
	// WorkloadIdentityProvider struct tags; no organization with a configured
	// provider was available.
	p := decodeWorkloadIdentityProvider(t, `{
		"id": "wip_0001",
		"object": "organization.workload_identity_provider",
		"name": "github-actions",
		"description": "CI deploys",
		"enabled": true,
		"type": "oidc",
		"issuer": "https://token.actions.githubusercontent.com",
		"audience": "https://api.openai.com",
		"created_at": 1760000000,
		"updated_at": 1760000500,
		"attribute_transformations": [
			{"attribute": "repository", "expression": "assertion.repository"},
			{"attribute": "ref", "expression": "assertion.ref"}
		],
		"verification": {
			"type": "discovery",
			"discovery_url": "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
		}
	}`)

	args := workloadIdentityProviderArgs(p)
	assert.Equal(t, "wip_0001", args["__id"].Value)
	assert.Equal(t, "wip_0001", args["id"].Value)
	assert.Equal(t, "github-actions", args["name"].Value)
	assert.Equal(t, "CI deploys", args["description"].Value)
	assert.Equal(t, true, args["enabled"].Value)
	assert.Equal(t, "oidc", args["type"].Value)
	assert.Equal(t, "https://token.actions.githubusercontent.com", args["issuer"].Value)
	assert.Equal(t, "https://api.openai.com", args["audience"].Value)
	assert.Equal(t, "discovery", args["verificationType"].Value)
	assert.Equal(t, "https://token.actions.githubusercontent.com/.well-known/openid-configuration", args["discoveryUrl"].Value)
	assert.Nil(t, args["jwks"].Value, "a discovery provider has no uploaded key set")
	assert.Equal(t, map[string]any{
		"repository": "assertion.repository",
		"ref":        "assertion.ref",
	}, args["attributeTransformations"].Value)
	assert.Equal(t, time.Unix(1760000000, 0), *args["createdAt"].Value.(*time.Time))
	assert.Equal(t, time.Unix(1760000500, 0), *args["updatedAt"].Value.(*time.Time))
}

func TestWorkloadIdentityProviderArgsUploadedJwks(t *testing.T) {
	// Synthetic: uploaded key set, disabled provider, no transformations.
	p := decodeWorkloadIdentityProvider(t, `{
		"id": "wip_0002",
		"name": "on-prem",
		"description": "",
		"enabled": false,
		"type": "oidc",
		"issuer": "https://idp.example.com",
		"audience": "openai",
		"created_at": 1760000000,
		"updated_at": 1760000000,
		"attribute_transformations": [],
		"verification": {
			"type": "uploaded_jwks",
			"jwks": {"keys": [{"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB"}]}
		}
	}`)

	args := workloadIdentityProviderArgs(p)
	assert.Equal(t, false, args["enabled"].Value)
	assert.Equal(t, "uploaded_jwks", args["verificationType"].Value)
	assert.Nil(t, args["discoveryUrl"].Value, "an uploaded key set has no discovery URL")
	jwks, ok := args["jwks"].Value.(map[string]any)
	require.True(t, ok)
	keys := jwks["keys"].([]any)
	require.Len(t, keys, 1)
	assert.Equal(t, "k1", keys[0].(map[string]any)["kid"])
	assert.Empty(t, args["attributeTransformations"].Value)
}

func TestWorkloadIdentityProviderArgsUnknownVerification(t *testing.T) {
	// Synthetic: a verification type the SDK does not know leaves both sides null.
	p := decodeWorkloadIdentityProvider(t, `{
		"id": "wip_0003", "name": "x", "issuer": "https://x", "audience": "a",
		"verification": {"type": "something_new", "discovery_url": "https://ignored"}
	}`)
	args := workloadIdentityProviderArgs(p)
	assert.Equal(t, "something_new", args["verificationType"].Value)
	assert.Nil(t, args["discoveryUrl"].Value)
	assert.Nil(t, args["jwks"].Value)
}

func TestFederationRuleArgsRestricted(t *testing.T) {
	// Synthetic: restricted rule with matchers of every value type the SDK's
	// FederationRuleAttributeMatcherUnion allows.
	fr := decodeFederationRule(t, `{
		"id": "wifr_0001",
		"object": "organization.workload_identity_federation_rule",
		"name": "deploy-main",
		"description": "main branch only",
		"enabled": true,
		"project_id": "proj_abc",
		"service_account_id": "svc_acct_123",
		"workload_identity_provider_id": "wip_0001",
		"created_at": 1760000000,
		"updated_at": 1760000100,
		"attribute_matchers": {
			"repository": "acme/app",
			"protected": true,
			"run_attempt": 1,
			"weight": 0.5
		},
		"permissions": {"type": "restricted", "scopes": ["model.request", "api.files.read"]}
	}`)

	args, err := federationRuleArgs("wip_0001", fr)
	require.NoError(t, err)
	assert.Equal(t, "wip_0001/wifr_0001", args["__id"].Value)
	assert.Equal(t, "wifr_0001", args["id"].Value)
	assert.Equal(t, "deploy-main", args["name"].Value)
	assert.Equal(t, "main branch only", args["description"].Value)
	assert.Equal(t, true, args["enabled"].Value)
	assert.Equal(t, map[string]any{
		"repository":  "acme/app",
		"protected":   true,
		"run_attempt": float64(1),
		"weight":      0.5,
	}, args["attributeMatchers"].Value)
	assert.Equal(t, "restricted", args["permissionType"].Value)
	assert.Equal(t, []any{"model.request", "api.files.read"}, args["permissionScopes"].Value)
	assert.Equal(t, time.Unix(1760000100, 0), *args["updatedAt"].Value.(*time.Time))
}

func TestFederationRuleArgsServiceAccountDefault(t *testing.T) {
	// Synthetic: a rule carrying the service account's own permissions has no
	// scopes, which must read as null rather than as an empty restriction.
	fr := decodeFederationRule(t, `{
		"id": "wifr_0002", "name": "any", "enabled": false,
		"project_id": "proj_abc", "service_account_id": "svc_acct_123",
		"attribute_matchers": {},
		"permissions": {"type": "service_account_default"}
	}`)

	args, err := federationRuleArgs("wip_0001", fr)
	require.NoError(t, err)
	assert.Equal(t, false, args["enabled"].Value)
	assert.Equal(t, "service_account_default", args["permissionType"].Value)
	assert.Nil(t, args["permissionScopes"].Value)
	assert.Equal(t, map[string]any{}, args["attributeMatchers"].Value)
}

func TestFederationRuleIdsAreDistinctAcrossProviders(t *testing.T) {
	// Synthetic: the same rule id under two providers must not share a cache entry.
	fr := decodeFederationRule(t, `{"id": "wifr_0001", "permissions": {"type": "service_account_default"}}`)
	a, err := federationRuleArgs("wip_a", fr)
	require.NoError(t, err)
	b, err := federationRuleArgs("wip_b", fr)
	require.NoError(t, err)
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
}

func federationRuleFixture(projectID, serviceAccountID string) *mqlOpenaiWorkloadIdentityProviderFederationRule {
	return &mqlOpenaiWorkloadIdentityProviderFederationRule{
		Id: plugin.TValue[string]{Data: projectID + "/" + serviceAccountID, State: plugin.StateIsSet},
		mqlOpenaiWorkloadIdentityProviderFederationRuleInternal: mqlOpenaiWorkloadIdentityProviderFederationRuleInternal{
			cacheProjectId:        projectID,
			cacheServiceAccountId: serviceAccountID,
		},
	}
}

func TestFederationRulesFor(t *testing.T) {
	// Synthetic: rules granting different service accounts and projects.
	match := federationRuleFixture("proj_a", "svc_1")
	otherAccount := federationRuleFixture("proj_a", "svc_2")
	otherProject := federationRuleFixture("proj_b", "svc_1")
	rules := []any{match, otherAccount, otherProject}

	assert.Equal(t, []any{match}, federationRulesFor(rules, "proj_a", "svc_1"))
	assert.Empty(t, federationRulesFor(rules, "proj_c", "svc_1"))
	assert.Empty(t, federationRulesFor(rules, "proj_a", ""), "an account with no id matches nothing")
	assert.Equal(t, []any{match, otherProject}, federationRulesFor(rules, "", "svc_1"))
}
