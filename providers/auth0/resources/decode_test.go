// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/auth0/go-auth0/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientAnonymousSessionsDecode(t *testing.T) {
	var on management.Client
	require.NoError(t, json.Unmarshal([]byte(`{"client_id":"a","anonymous_sessions":{"active":true}}`), &on))
	got := anonymousSessionsActive(on.AnonymousSessions)
	require.NotNil(t, got)
	assert.True(t, *got)

	var off management.Client
	require.NoError(t, json.Unmarshal([]byte(`{"client_id":"a","anonymous_sessions":{"active":false}}`), &off))
	got = anonymousSessionsActive(off.AnonymousSessions)
	require.NotNil(t, got)
	assert.False(t, *got)

	var absent management.Client
	require.NoError(t, json.Unmarshal([]byte(`{"client_id":"a"}`), &absent))
	assert.Nil(t, anonymousSessionsActive(absent.AnonymousSessions))
}

func TestMyOrganizationArgs(t *testing.T) {
	var c management.Client
	require.NoError(t, json.Unmarshal([]byte(`{
		"client_id": "a",
		"my_organization_configuration": {
			"allowed_strategies": ["okta", "samlp"],
			"connection_deletion_behavior": "allow_if_empty",
			"invitation_landing_client_id": "landing",
			"enforce_permission_ceiling": true,
			"enforce_self_assignment_restriction": false
		}
	}`), &c))
	require.NotNil(t, c.MyOrganizationConfiguration)

	args := myOrganizationArgs(c.MyOrganizationConfiguration)
	assert.Equal(t, true, args["enforcePermissionCeiling"].Value)
	assert.Equal(t, false, args["enforceSelfAssignmentRestriction"].Value)
	assert.Equal(t, []any{"okta", "samlp"}, args["allowedStrategies"].Value)
	assert.Equal(t, "allow_if_empty", args["connectionDeletionBehavior"].Value)
	require.NotNil(t, c.MyOrganizationConfiguration.InvitationLandingClientID)
	assert.Equal(t, "landing", *c.MyOrganizationConfiguration.InvitationLandingClientID)

	// Settings the API omits stay null rather than reading as false or empty.
	empty := myOrganizationArgs(&management.MyOrganizationConfiguration{})
	assert.Nil(t, empty["enforcePermissionCeiling"].Value)
	assert.Nil(t, empty["enforceSelfAssignmentRestriction"].Value)
	assert.Nil(t, empty["allowedStrategies"].Value)
	assert.Nil(t, empty["connectionDeletionBehavior"].Value)
}

func TestNewMyOrganizationNilConfig(t *testing.T) {
	id := "a"
	d, err := newMqlAuth0ClientMyOrganization(nil, &id, nil)
	require.NoError(t, err)
	assert.Nil(t, d.Value)
}

func TestSubjectTypePolicies(t *testing.T) {
	var rs management.ResourceServer
	require.NoError(t, json.Unmarshal([]byte(`{
		"subject_type_authorization": {
			"user": {"policy": "allow_all"},
			"client": {"policy": "require_client_grant"},
			"anonymous_user": {"policy": "deny_all"}
		}
	}`), &rs))
	user, client, anon := subjectTypePolicies(rs.SubjectTypeAuthorization)
	require.NotNil(t, user)
	require.NotNil(t, client)
	require.NotNil(t, anon)
	assert.Equal(t, "allow_all", *user)
	assert.Equal(t, "require_client_grant", *client)
	assert.Equal(t, "deny_all", *anon)

	var partial management.ResourceServer
	require.NoError(t, json.Unmarshal([]byte(`{"subject_type_authorization": {"client": {"policy": "deny_all"}}}`), &partial))
	user, client, anon = subjectTypePolicies(partial.SubjectTypeAuthorization)
	assert.Nil(t, user)
	require.NotNil(t, client)
	assert.Equal(t, "deny_all", *client)
	assert.Nil(t, anon)

	user, client, anon = subjectTypePolicies(nil)
	assert.Nil(t, user)
	assert.Nil(t, client)
	assert.Nil(t, anon)
}

func TestAccessTokenCustomClaims(t *testing.T) {
	var rs management.ResourceServer
	require.NoError(t, json.Unmarshal([]byte(`{
		"access_token": {"claims_mapping": {"custom_claims": [
			{"name": "tenant", "expression": "user.app_metadata.tenant"},
			{"name": "", "expression": "ignored"},
			{"expression": "no name"},
			{"name": "flag"}
		]}}
	}`), &rs))
	got := accessTokenCustomClaims(rs.AccessToken)
	assert.Equal(t, map[string]any{
		"tenant": "user.app_metadata.tenant",
		"flag":   "",
	}, got.Value)

	assert.Nil(t, accessTokenCustomClaims(nil).Value)
	assert.Nil(t, accessTokenCustomClaims(&management.ResourceServerAccessToken{}).Value)
	assert.Nil(t, accessTokenCustomClaims(&management.ResourceServerAccessToken{
		ClaimsMapping: &management.ResourceServerAccessTokenClaimsMapping{},
	}).Value)
}

func TestTenantSessionSettings(t *testing.T) {
	var tn management.Tenant
	require.NoError(t, json.Unmarshal([]byte(`{"sessions": {
		"oidc_logout_prompt_enabled": false,
		"anonymous": {"lifetime_in_minutes": 30, "activate_cookie": true}
	}}`), &tn))
	prompt, lifetime, cookie := tenantSessionSettings(tn.Sessions)
	require.NotNil(t, prompt)
	require.NotNil(t, lifetime)
	require.NotNil(t, cookie)
	assert.False(t, *prompt)
	assert.Equal(t, 30, *lifetime)
	assert.True(t, *cookie)

	var noAnon management.Tenant
	require.NoError(t, json.Unmarshal([]byte(`{"sessions": {"oidc_logout_prompt_enabled": true}}`), &noAnon))
	prompt, lifetime, cookie = tenantSessionSettings(noAnon.Sessions)
	require.NotNil(t, prompt)
	assert.True(t, *prompt)
	assert.Nil(t, lifetime)
	assert.Nil(t, cookie)

	prompt, lifetime, cookie = tenantSessionSettings(nil)
	assert.Nil(t, prompt)
	assert.Nil(t, lifetime)
	assert.Nil(t, cookie)
}
