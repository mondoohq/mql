// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestAccessPolicies(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("access_policies"))
	})

	result, err := one.accessPolicies()
	require.NoError(t, err)
	require.Len(t, result, 1)

	policy := result[0].(*mqlCloudflareOneAccessPolicy)
	assert.Equal(t, "policy-001", policy.Id.Data)
	assert.Equal(t, "Allow Engineers", policy.Name.Data)
	assert.Equal(t, "allow", policy.Decision.Data)
	assert.Equal(t, int64(1), policy.Precedence.Data)
}

func TestAccessGroups(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/groups", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("access_groups"))
	})

	result, err := one.accessGroups()
	require.NoError(t, err)
	require.Len(t, result, 1)

	group := result[0].(*mqlCloudflareOneAccessGroup)
	assert.Equal(t, "group-001", group.Id.Data)
	assert.Equal(t, "Engineering Team", group.Name.Data)
}

func TestServiceTokens(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/service_tokens", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("service_tokens"))
	})

	result, err := one.serviceTokens()
	require.NoError(t, err)
	require.Len(t, result, 1)

	token := result[0].(*mqlCloudflareOneServiceToken)
	assert.Equal(t, "svctoken-001", token.Id.Data)
	assert.Equal(t, "CI/CD Token", token.Name.Data)
	assert.Equal(t, "client-abc123", token.ClientId.Data)
	assert.Equal(t, "8760h", token.Duration.Data)
	assert.False(t, token.ExpiresAt.Data.IsZero())
	assert.False(t, token.LastSeenAt.Data.IsZero())
}

func TestOrganization(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/organizations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("access_organization"))
	})

	result, err := one.organization()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "My Organization", result.Name.Data)
	assert.Equal(t, "myorg.cloudflareaccess.com", result.AuthDomain.Data)
	assert.Equal(t, true, result.AutoRedirectToIdentity.Data)
	assert.Equal(t, "24h", result.SessionDuration.Data)
	assert.Equal(t, true, result.AllowAuthenticateViaWarp.Data)
}

func TestIdentityProviders(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/access/identity_providers", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("identity_providers"))
	})

	result, err := one.identityProviders()
	require.NoError(t, err)
	require.Len(t, result, 3)

	// Okta IdP — type=okta, scim enabled, no SAML fields
	okta := result[0].(*mqlCloudflareOneIdp)
	assert.Equal(t, "idp-okta-001", okta.Id.Data)
	assert.Equal(t, "Corp Okta", okta.Name.Data)
	assert.Equal(t, "okta", okta.Type.Data)
	assert.False(t, okta.Saml.Data, "okta should not be flagged saml=true")
	assert.True(t, okta.ScimEnabled.Data)
	assert.Equal(t, "email", okta.EmailAttributeName.Data)
	assert.Equal(t, []any{"groups", "department"}, okta.Attributes.Data)

	// SAML IdP — exercises the saml flag, SSO/issuer URL, signRequest, public cert
	saml := result[1].(*mqlCloudflareOneIdp)
	assert.Equal(t, "saml", saml.Type.Data)
	assert.True(t, saml.Saml.Data, "type=saml should set saml=true")
	assert.Equal(t, "https://idp.example.com/saml/sso", saml.SsoTargetUrl.Data)
	assert.Equal(t, "https://idp.example.com/saml/metadata", saml.IssuerUrl.Data)
	assert.True(t, saml.SignRequest.Data)
	assert.NotEmpty(t, saml.IdpPublicCert.Data)
	assert.False(t, saml.ScimEnabled.Data)

	// One-time PIN — minimal config
	otp := result[2].(*mqlCloudflareOneIdp)
	assert.Equal(t, "onetimepin", otp.Type.Data)
	assert.False(t, otp.Saml.Data)
	assert.False(t, otp.ScimEnabled.Data)
	assert.Empty(t, otp.SsoTargetUrl.Data)
}

// warpAuthNonBrowser401 is optional on the organization payload. An absent
// value has to stay null: reporting false would claim the organization
// redirects failed WARP authentication to a login page, which is a statement
// about its behavior that the API never made.
func TestOrganizationWarpAuthNonBrowser401(t *testing.T) {
	for _, tc := range []struct {
		name     string
		field    string
		wantData bool
		wantNull bool
	}{
		{name: "enabled", field: `,"warp_auth_non_browser_401":true`, wantData: true},
		{name: "disabled", field: `,"warp_auth_non_browser_401":false`, wantData: false},
		{name: "absent", field: ``, wantNull: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			one := createTestOne(t, env)

			env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/organizations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
				jsonResponse(w, fmt.Sprintf(
					`{"success":true,"result":{"name":"My Organization","auth_domain":"myorg.cloudflareaccess.com"%s}}`,
					tc.field))
			})

			result, err := one.organization()
			require.NoError(t, err)
			require.NotNil(t, result)

			if tc.wantNull {
				assert.True(t, result.WarpAuthNonBrowser401.State&plugin.StateIsNull != 0,
					"an absent setting must read as null, not as false")
				return
			}
			assert.Equal(t, tc.wantData, result.WarpAuthNonBrowser401.Data)
		})
	}
}

// service_token_inactivity is an optional object on the organization payload.
// When it is absent, all three fields must read as null: reporting enabled as
// false would claim inactive tokens are known to be left alone.
func TestOrganizationServiceTokenInactivity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		field      string
		wantNull   bool
		wantOn     bool
		wantAction string
		wantDays   int64
	}{
		{
			name:       "enabled delete",
			field:      `,"service_token_inactivity":{"enabled":true,"action":"delete","inactivity_threshold_days":90}`,
			wantOn:     true,
			wantAction: "delete",
			wantDays:   90,
		},
		{
			name:       "disabled",
			field:      `,"service_token_inactivity":{"enabled":false,"action":"disable","inactivity_threshold_days":30}`,
			wantOn:     false,
			wantAction: "disable",
			wantDays:   30,
		},
		{name: "absent", field: ``, wantNull: true},
		{name: "null", field: `,"service_token_inactivity":null`, wantNull: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			one := createTestOne(t, env)

			env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/organizations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
				jsonResponse(w, fmt.Sprintf(
					`{"success":true,"result":{"name":"My Organization","auth_domain":"myorg.cloudflareaccess.com"%s}}`,
					tc.field))
			})

			result, err := one.organization()
			require.NoError(t, err)
			require.NotNil(t, result)

			if tc.wantNull {
				assert.True(t, result.ServiceTokenInactivityEnabled.State&plugin.StateIsNull != 0,
					"an absent setting must read as null, not as false")
				assert.True(t, result.ServiceTokenInactivityAction.State&plugin.StateIsNull != 0)
				assert.True(t, result.ServiceTokenInactivityThresholdDays.State&plugin.StateIsNull != 0)
				return
			}
			assert.True(t, result.ServiceTokenInactivityEnabled.State&plugin.StateIsNull == 0)
			assert.Equal(t, tc.wantOn, result.ServiceTokenInactivityEnabled.Data)
			assert.Equal(t, tc.wantAction, result.ServiceTokenInactivityAction.Data)
			assert.Equal(t, tc.wantDays, result.ServiceTokenInactivityThresholdDays.Data)
		})
	}
}
