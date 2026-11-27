// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"
	"time"

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

// strict_service_token_auth is optional on the organization payload. An absent
// value has to stay null: false would claim failed service-token requests are
// known to be redirected to a login page.
func TestOrganizationStrictServiceTokenAuth(t *testing.T) {
	for _, tc := range []struct {
		name     string
		field    string
		wantData bool
		wantNull bool
	}{
		{name: "enabled", field: `,"strict_service_token_auth":true`, wantData: true},
		{name: "disabled", field: `,"strict_service_token_auth":false`, wantData: false},
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
				assert.True(t, result.StrictServiceTokenAuth.State&plugin.StateIsNull != 0,
					"an absent setting must read as null, not as false")
				return
			}
			assert.True(t, result.StrictServiceTokenAuth.State&plugin.StateIsNull == 0)
			assert.Equal(t, tc.wantData, result.StrictServiceTokenAuth.Data)
		})
	}
}

// Synthetic: disable_end_user_app_creation is optional on the organization
// payload. An absent value stays null; false would claim end users are known
// to be allowed to create applications.
func TestOrganizationDisableEndUserAppCreation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		field    string
		wantData bool
		wantNull bool
	}{
		{name: "disabled for end users", field: `,"disable_end_user_app_creation":true`, wantData: true},
		{name: "allowed for end users", field: `,"disable_end_user_app_creation":false`, wantData: false},
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
				assert.True(t, result.DisableEndUserAppCreation.IsNull())
				return
			}
			assert.False(t, result.DisableEndUserAppCreation.IsNull())
			assert.Equal(t, tc.wantData, result.DisableEndUserAppCreation.Data)
		})
	}
}

func serveServiceTokens(env *testEnv, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/service_tokens", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[`+body+`],"result_info":{"page":1,"total_pages":1}}`)
	})
}

// Synthetic: a token a secret scanning partner reported as leaked, and one
// that was never reported; no live account was checked. The leak fields must
// read null on the unreported token rather than as an empty string or year 1.
func TestServiceTokenLeakFields(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveServiceTokens(env, `
		{"id":"tok-leaked","name":"leaked","client_id":"c1","enabled":false,
		 "leak_reported_at":"2026-03-04T05:06:07Z","leak_reporter":"github",
		 "leak_report_url":"https://github.com/example/repo/blob/main/.env"},
		{"id":"tok-clean","name":"clean","client_id":"c2","enabled":true}`)

	result, err := one.serviceTokens()
	require.NoError(t, err)
	require.Len(t, result, 2)

	leaked := result[0].(*mqlCloudflareOneServiceToken)
	assert.False(t, leaked.Enabled.IsNull())
	assert.False(t, leaked.Enabled.Data)
	require.False(t, leaked.LeakReportedAt.IsNull())
	assert.Equal(t, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), leaked.LeakReportedAt.Data.UTC())
	assert.Equal(t, "github", leaked.LeakReporter.Data)
	assert.Equal(t, "https://github.com/example/repo/blob/main/.env", leaked.LeakReportUrl.Data)

	clean := result[1].(*mqlCloudflareOneServiceToken)
	assert.True(t, clean.Enabled.Data)
	assert.True(t, clean.LeakReportedAt.IsNull())
	assert.True(t, clean.LeakReporter.IsNull())
	assert.True(t, clean.LeakReportUrl.IsNull())
}

// Synthetic: a token record without the enabled flag; no live account was
// checked. Absent must read null, not as disabled.
func TestServiceTokenEnabledAbsent(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveServiceTokens(env, `{"id":"tok-old","name":"old","client_id":"c3"}`)

	result, err := one.serviceTokens()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.True(t, result[0].(*mqlCloudflareOneServiceToken).Enabled.IsNull())
}

// Synthetic: an access group with include, require and exclude rules; no live
// account was checked.
func TestAccessGroupRules(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/groups", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"g1","name":"Engineering",
			 "include":[{"email_domain":{"domain":"example.com"}}],
			 "require":[{"group":{"id":"g-mfa"}}],
			 "exclude":[{"email":{"email":"contractor@example.com"}}]},
			{"id":"g2","name":"Bare"}
		],"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := one.accessGroups()
	require.NoError(t, err)
	require.Len(t, result, 2)

	g := result[0].(*mqlCloudflareOneAccessGroup)
	assert.Equal(t, []any{map[string]any{"email_domain": map[string]any{"domain": "example.com"}}}, g.Include.Data)
	assert.Equal(t, []any{map[string]any{"group": map[string]any{"id": "g-mfa"}}}, g.Require.Data)
	assert.Equal(t, []any{map[string]any{"email": map[string]any{"email": "contractor@example.com"}}}, g.Exclude.Data)

	bare := result[1].(*mqlCloudflareOneAccessGroup)
	assert.Equal(t, []any{}, bare.Include.Data)
	assert.Equal(t, []any{}, bare.Exclude.Data)
}

// Synthetic: a reusable account-level policy with every new setting, and one
// without them; no live account was checked.
func TestAccessPolicySettings(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"p1","name":"Admins","decision":"allow","app_count":0,
			 "approval_required":true,"isolation_required":false,"purpose_justification_required":true,
			 "session_duration":"30m",
			 "mfa_config":{"allowed_authenticators":["security_key"],"mfa_disabled":false,"session_duration":"1h"}},
			{"id":"p2","name":"Minimal","decision":"deny","app_count":3}
		],"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := one.accessPolicies()
	require.NoError(t, err)
	require.Len(t, result, 2)

	p := result[0].(*mqlCloudflareOneAccessPolicy)
	assert.True(t, p.ApprovalRequired.Data)
	assert.False(t, p.IsolationRequired.IsNull())
	assert.False(t, p.IsolationRequired.Data)
	assert.True(t, p.PurposeJustificationRequired.Data)
	assert.Equal(t, "30m", p.SessionDuration.Data)
	assert.False(t, p.MfaDisabled.IsNull())
	assert.False(t, p.MfaDisabled.Data)
	assert.Equal(t, []any{"security_key"}, p.MfaAllowedAuthenticators.Data)
	// An unattached reusable policy reports 0, which must not read as null.
	assert.False(t, p.AppCount.IsNull())
	assert.Equal(t, int64(0), p.AppCount.Data)

	minimal := result[1].(*mqlCloudflareOneAccessPolicy)
	assert.Equal(t, int64(3), minimal.AppCount.Data)
	assert.True(t, minimal.ApprovalRequired.IsNull())
	assert.True(t, minimal.IsolationRequired.IsNull())
	assert.True(t, minimal.PurposeJustificationRequired.IsNull())
	assert.True(t, minimal.SessionDuration.IsNull())
	assert.True(t, minimal.MfaDisabled.IsNull())
	assert.True(t, minimal.MfaAllowedAuthenticators.IsNull())
}

func serveAccessApps(env *testEnv, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/access/apps", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[`+body+`],"result_info":{"page":1,"total_pages":1}}`)
	})
}

// Synthetic: a self-hosted app with the new settings and public and private
// destinations, plus an embedded policy; no live account was checked. The
// embedded policy shape has no app_count, so appCount must read null there.
func TestAppSettingsAndDestinations(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveAccessApps(env, `{"id":"app-1","name":"Wiki","domain":"wiki.example.com","type":"self_hosted",
		"allow_authenticate_via_warp":true,"allow_iframe":false,
		"read_service_tokens_from_header":"Authorization","path_cookie_attribute":true,
		"mfa_config":{"allowed_authenticators":["totp","biometrics"],"mfa_disabled":true},
		"destinations":[
			{"type":"public","uri":"wiki.example.com/docs"},
			{"type":"private","hostname":"wiki.internal","cidr":"10.0.0.0/24","port_range":"443","l4_protocol":"tcp","vnet_id":"vnet-1"}
		],
		"policies":[{"id":"","name":"inline","decision":"allow","precedence":1,"approval_required":true}]}`)

	result, err := one.apps()
	require.NoError(t, err)
	require.Len(t, result, 1)

	app := result[0].(*mqlCloudflareOneApp)
	assert.True(t, app.AllowAuthenticateViaWarp.Data)
	assert.False(t, app.AllowIframe.IsNull())
	assert.False(t, app.AllowIframe.Data)
	assert.Equal(t, "Authorization", app.ReadServiceTokensFromHeader.Data)
	assert.True(t, app.PathCookieAttribute.Data)
	assert.True(t, app.MfaDisabled.Data)
	assert.Equal(t, []any{"totp", "biometrics"}, app.MfaAllowedAuthenticators.Data)
	assert.Equal(t, []any{
		map[string]any{"type": "public", "uri": "wiki.example.com/docs"},
		map[string]any{"type": "private", "hostname": "wiki.internal", "cidr": "10.0.0.0/24",
			"portRange": "443", "l4Protocol": "tcp", "vnetId": "vnet-1"},
	}, app.Destinations.Data)

	policies, err := app.policies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	embedded := policies[0].(*mqlCloudflareOneAccessPolicy)
	assert.True(t, embedded.ApprovalRequired.Data)
	assert.True(t, embedded.AppCount.IsNull(), "an embedded policy reports no app count")
}

// Synthetic: an app record that carries none of the new settings, as an older
// or SaaS app record would; no live account was checked.
func TestAppSettingsAbsent(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveAccessApps(env, `{"id":"app-2","name":"Bare","domain":"bare.example.com","type":"saas"}`)

	result, err := one.apps()
	require.NoError(t, err)
	require.Len(t, result, 1)

	app := result[0].(*mqlCloudflareOneApp)
	assert.True(t, app.AllowAuthenticateViaWarp.IsNull())
	assert.True(t, app.AllowIframe.IsNull())
	assert.True(t, app.ReadServiceTokensFromHeader.IsNull())
	assert.True(t, app.PathCookieAttribute.IsNull())
	assert.True(t, app.MfaDisabled.IsNull())
	assert.True(t, app.MfaAllowedAuthenticators.IsNull())
	assert.True(t, app.Destinations.IsNull())
}

func serveOrganization(env *testEnv, fields string) {
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/organizations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":{"name":"My Organization","auth_domain":"myorg.cloudflareaccess.com"`+fields+`}}`)
	})
}

// Synthetic: an organization denying unmatched requests with two exempted
// zones, one listed by the token and one not, and an MFA configuration; no
// live account was checked.
func TestOrganizationDenyUnmatchedAndMfa(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveOrganization(env, `,"deny_unmatched_requests":true,
		"deny_unmatched_requests_exempted_zone_names":["Example.com.","not-listed.example"],
		"mfa_required_for_all_apps":false,
		"mfa_config":{"allowed_authenticators":["totp","security_key"],"session_duration":"24h"}`)
	env.Mux.HandleFunc("/zones", pagedFixture("zones"))

	org, err := one.organization()
	require.NoError(t, err)
	require.NotNil(t, org)

	assert.True(t, org.DenyUnmatchedRequests.Data)
	assert.False(t, org.MfaRequiredForAllApps.IsNull())
	assert.False(t, org.MfaRequiredForAllApps.Data)
	assert.Equal(t, []any{"totp", "security_key"}, org.MfaAllowedAuthenticators.Data)
	assert.Equal(t, "24h", org.MfaSessionDuration.Data)

	zones, err := org.denyUnmatchedRequestsExemptedZones()
	require.NoError(t, err)
	require.Len(t, zones, 1, "a zone the token cannot list is left out")
	assert.Equal(t, testZoneID, zones[0].(*mqlCloudflareZone).Id.Data)
}

// Synthetic: an organization that reports none of the new settings; no live
// account was checked. Every field reads null and resolving the exempted
// zones issues no zone list request.
func TestOrganizationDenyUnmatchedAbsent(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	serveOrganization(env, ``)
	env.Mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		t.Error("no zone list request expected when no zones are exempted")
	})

	org, err := one.organization()
	require.NoError(t, err)
	require.NotNil(t, org)

	assert.True(t, org.DenyUnmatchedRequests.IsNull())
	assert.True(t, org.MfaRequiredForAllApps.IsNull())
	assert.True(t, org.MfaAllowedAuthenticators.IsNull())
	assert.True(t, org.MfaSessionDuration.IsNull())

	zones, err := org.denyUnmatchedRequestsExemptedZones()
	require.NoError(t, err)
	assert.Nil(t, zones)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, org.DenyUnmatchedRequestsExemptedZones.State)
}

// Synthetic: an Entra ID connector with SCIM deprovisioning configured, and a
// one-time PIN provider that reports neither SCIM nor OIDC settings; no live
// account was checked. The type-dependent fields must read null on the
// provider that does not carry them.
func TestIdentityProviderScimAndOidcSettings(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/access/identity_providers", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"idp-entra","name":"Entra","type":"azureAD",
			 "config":{"client_id":"cid","client_secret":"must-not-leak","pkce_enabled":false,"conditional_access_enabled":true},
			 "scim_config":{"enabled":true,"user_deprovision":true,"seat_deprovision":false,
			   "identity_update_behavior":"reauth","secret":"must-not-leak"}},
			{"id":"idp-otp","name":"PIN","type":"onetimepin","config":{}}
		],"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := one.identityProviders()
	require.NoError(t, err)
	require.Len(t, result, 2)

	entra := result[0].(*mqlCloudflareOneIdp)
	assert.True(t, entra.ScimUserDeprovision.Data)
	assert.False(t, entra.ScimSeatDeprovision.IsNull())
	assert.False(t, entra.ScimSeatDeprovision.Data)
	assert.Equal(t, "reauth", entra.ScimIdentityUpdateBehavior.Data)
	assert.False(t, entra.PkceEnabled.IsNull())
	assert.False(t, entra.PkceEnabled.Data)
	assert.True(t, entra.ConditionalAccessEnabled.Data)

	otp := result[1].(*mqlCloudflareOneIdp)
	assert.True(t, otp.ScimUserDeprovision.IsNull())
	assert.True(t, otp.ScimSeatDeprovision.IsNull())
	assert.True(t, otp.ScimIdentityUpdateBehavior.IsNull())
	assert.True(t, otp.PkceEnabled.IsNull())
	assert.True(t, otp.ConditionalAccessEnabled.IsNull())
}
