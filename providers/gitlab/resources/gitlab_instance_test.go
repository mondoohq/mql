// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
)

// The group-hook repositoryUpdateEvents field shipped as a permanent false
// because the GitLab API never sent the attribute and the SDK typed it as a
// plain bool. Every posture field added here is decoded through a pointer for
// exactly that reason, and these tests pin the JSON tags and the absent case so
// the same bug cannot come back through a typo.

func newTestClient(t *testing.T, handler http.Handler) (*gitlab.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := gitlab.NewClient("test-token", gitlab.WithBaseURL(server.URL))
	require.NoError(t, err)
	return client, server
}

//
// Instance settings decoding
//

func TestInstanceSettingsPolicyDecodesEveryTag(t *testing.T) {
	// Values are deliberately distinct so a tag copied onto the wrong field
	// fails rather than coincidentally matching its neighbour.
	payload := []byte(`{
		"require_personal_access_token_expiry": true,
		"max_personal_access_token_lifetime": 30,
		"service_access_tokens_expiration_enforced": true,
		"allow_runner_registration_token": true,
		"runner_token_expiration_interval": 604800,
		"group_runner_token_expiration_interval": 1209600,
		"project_runner_token_expiration_interval": 2592000,
		"rsa_key_restriction": 2048,
		"dsa_key_restriction": -1,
		"ecdsa_key_restriction": 256,
		"ecdsa_sk_key_restriction": 384,
		"ed25519_key_restriction": 0,
		"ed25519_sk_key_restriction": -1,
		"max_login_attempts": 5,
		"failed_login_attempts_unlock_period_in_minutes": 15,
		"unique_ips_limit_enabled": true,
		"unique_ips_limit_per_user": 3,
		"unique_ips_limit_time_window": 3600,
		"disable_password_authentication_for_users_with_sso_identities": true,
		"login_recaptcha_protection_enabled": true,
		"admin_mode": true,
		"session_expire_from_init": true,
		"deactivate_dormant_users": true,
		"deactivate_dormant_users_period": 90,
		"enforce_ci_inbound_job_token_scope_enabled": true,
		"package_registry_allow_anyone_to_pull_option": true
	}`)

	policy := &instanceSettingsPolicy{}
	require.NoError(t, json.Unmarshal(payload, policy))

	require.NotNil(t, policy.RequirePersonalAccessTokenExpiry)
	assert.True(t, *policy.RequirePersonalAccessTokenExpiry)
	require.NotNil(t, policy.MaxPersonalAccessTokenLifetime)
	assert.EqualValues(t, 30, *policy.MaxPersonalAccessTokenLifetime)
	require.NotNil(t, policy.ServiceAccessTokensExpirationEnforced)
	assert.True(t, *policy.ServiceAccessTokensExpirationEnforced)
	require.NotNil(t, policy.AllowRunnerRegistrationToken)
	assert.True(t, *policy.AllowRunnerRegistrationToken)
	require.NotNil(t, policy.RunnerTokenExpirationInterval)
	assert.EqualValues(t, 604800, *policy.RunnerTokenExpirationInterval)
	require.NotNil(t, policy.GroupRunnerTokenExpirationInterval)
	assert.EqualValues(t, 1209600, *policy.GroupRunnerTokenExpirationInterval)
	require.NotNil(t, policy.ProjectRunnerTokenExpirationInterval)
	assert.EqualValues(t, 2592000, *policy.ProjectRunnerTokenExpirationInterval)

	require.NotNil(t, policy.RSAKeyRestriction)
	assert.EqualValues(t, 2048, *policy.RSAKeyRestriction)
	require.NotNil(t, policy.DSAKeyRestriction)
	assert.EqualValues(t, -1, *policy.DSAKeyRestriction)
	require.NotNil(t, policy.ECDSAKeyRestriction)
	assert.EqualValues(t, 256, *policy.ECDSAKeyRestriction)
	require.NotNil(t, policy.ECDSASKKeyRestriction)
	assert.EqualValues(t, 384, *policy.ECDSASKKeyRestriction)
	require.NotNil(t, policy.Ed25519KeyRestriction)
	assert.EqualValues(t, 0, *policy.Ed25519KeyRestriction)
	require.NotNil(t, policy.Ed25519SKKeyRestriction)
	assert.EqualValues(t, -1, *policy.Ed25519SKKeyRestriction)

	require.NotNil(t, policy.MaxLoginAttempts)
	assert.EqualValues(t, 5, *policy.MaxLoginAttempts)
	require.NotNil(t, policy.FailedLoginAttemptsUnlockPeriodInMinutes)
	assert.EqualValues(t, 15, *policy.FailedLoginAttemptsUnlockPeriodInMinutes)
	require.NotNil(t, policy.UniqueIPsLimitEnabled)
	assert.True(t, *policy.UniqueIPsLimitEnabled)
	require.NotNil(t, policy.UniqueIPsLimitPerUser)
	assert.EqualValues(t, 3, *policy.UniqueIPsLimitPerUser)
	require.NotNil(t, policy.UniqueIPsLimitTimeWindow)
	assert.EqualValues(t, 3600, *policy.UniqueIPsLimitTimeWindow)
	require.NotNil(t, policy.DisablePasswordAuthenticationForUsersWithSSOIdentities)
	assert.True(t, *policy.DisablePasswordAuthenticationForUsersWithSSOIdentities)
	require.NotNil(t, policy.LoginRecaptchaProtectionEnabled)
	assert.True(t, *policy.LoginRecaptchaProtectionEnabled)
	require.NotNil(t, policy.AdminMode)
	assert.True(t, *policy.AdminMode)
	require.NotNil(t, policy.SessionExpireFromInit)
	assert.True(t, *policy.SessionExpireFromInit)
	require.NotNil(t, policy.DeactivateDormantUsers)
	assert.True(t, *policy.DeactivateDormantUsers)
	require.NotNil(t, policy.DeactivateDormantUsersPeriod)
	assert.EqualValues(t, 90, *policy.DeactivateDormantUsersPeriod)

	require.NotNil(t, policy.EnforceCIInboundJobTokenScopeEnabled)
	assert.True(t, *policy.EnforceCIInboundJobTokenScopeEnabled)
	require.NotNil(t, policy.PackageRegistryAllowAnyoneToPullOption)
	assert.True(t, *policy.PackageRegistryAllowAnyoneToPullOption)
}

func TestInstanceSettingsPolicyKeepsUnreportedSettingsNull(t *testing.T) {
	t.Run("attribute absent from the response", func(t *testing.T) {
		// What an older self-managed release sends: the settings object is
		// there, the newer attributes are simply not in it.
		policy := &instanceSettingsPolicy{}
		require.NoError(t, json.Unmarshal([]byte(`{"id":1,"signup_enabled":true}`), policy))

		assert.Nil(t, policy.RequirePersonalAccessTokenExpiry,
			"an unreported setting must stay null, not report as not-enforced")
		assert.Nil(t, policy.AllowRunnerRegistrationToken)
		assert.Nil(t, policy.EnforceCIInboundJobTokenScopeEnabled)
		assert.Nil(t, policy.PackageRegistryAllowAnyoneToPullOption)
		assert.Nil(t, policy.AdminMode)
		assert.Nil(t, policy.DisablePasswordAuthenticationForUsersWithSSOIdentities)
		assert.Nil(t, policy.RSAKeyRestriction)
		assert.Nil(t, policy.MaxLoginAttempts)
		assert.Nil(t, policy.MaxPersonalAccessTokenLifetime)
	})

	t.Run("attribute explicitly null", func(t *testing.T) {
		// GitLab sends null for "no ceiling configured" on the lifetime and
		// lockout settings. That has to stay null too, not collapse to 0.
		policy := &instanceSettingsPolicy{}
		require.NoError(t, json.Unmarshal([]byte(`{
			"max_personal_access_token_lifetime": null,
			"max_login_attempts": null,
			"runner_token_expiration_interval": null
		}`), policy))

		assert.Nil(t, policy.MaxPersonalAccessTokenLifetime)
		assert.Nil(t, policy.MaxLoginAttempts)
		assert.Nil(t, policy.RunnerTokenExpirationInterval)
	})

	t.Run("false is preserved as false", func(t *testing.T) {
		policy := &instanceSettingsPolicy{}
		require.NoError(t, json.Unmarshal([]byte(`{
			"require_personal_access_token_expiry": false,
			"enforce_ci_inbound_job_token_scope_enabled": false
		}`), policy))

		require.NotNil(t, policy.RequirePersonalAccessTokenExpiry)
		assert.False(t, *policy.RequirePersonalAccessTokenExpiry)
		require.NotNil(t, policy.EnforceCIInboundJobTokenScopeEnabled)
		assert.False(t, *policy.EnforceCIInboundJobTokenScopeEnabled)
	})
}

func TestGetInstanceSettingsReadsBothViewsFromOneResponse(t *testing.T) {
	calls := 0
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v4/application/settings", r.URL.Path)
		fmt.Fprint(w, `{
			"id": 1,
			"require_two_factor_authentication": true,
			"allow_runner_registration_token": false,
			"unique_ips_limit_per_user": 7
		}`)
	}))

	settings, policy, err := getInstanceSettings(client)
	require.NoError(t, err)

	assert.Equal(t, 1, calls, "both views must come from a single request")
	assert.True(t, settings.RequireTwoFactorAuthentication)
	require.NotNil(t, policy.AllowRunnerRegistrationToken)
	assert.False(t, *policy.AllowRunnerRegistrationToken)
	require.NotNil(t, policy.UniqueIPsLimitPerUser)
	assert.EqualValues(t, 7, *policy.UniqueIPsLimitPerUser)
}

func TestSetInstanceSettingsPolicyArgsReportsUnreadSettingsAsNull(t *testing.T) {
	// An empty policy is what an instance that reports none of these settings
	// produces. Every field has to land as null; a fabricated false would pass
	// a `settings.adminMode` style assertion without anything being checked.
	args := map[string]*llx.RawData{}
	setInstanceSettingsPolicyArgs(args, &instanceSettingsPolicy{})

	require.NotEmpty(t, args)
	for key, value := range args {
		require.NotNil(t, value, key)
		assert.Nil(t, value.Value, "%s must be null when the instance did not report it", key)
	}
}

func TestSetInstanceSettingsPolicyArgsCoversEveryDecodedSetting(t *testing.T) {
	args := map[string]*llx.RawData{}
	setInstanceSettingsPolicyArgs(args, &instanceSettingsPolicy{})

	assert.Equal(t, reflect.TypeOf(instanceSettingsPolicy{}).NumField(), len(args),
		"every setting decoded from the response has to reach the resource, or it is dead schema")
}

func TestSetInstanceSettingsPolicyArgsCarriesReportedValues(t *testing.T) {
	enabled, disabled := true, false
	lifetime := int64(30)

	args := map[string]*llx.RawData{}
	setInstanceSettingsPolicyArgs(args, &instanceSettingsPolicy{
		AllowRunnerRegistrationToken:         &enabled,
		EnforceCIInboundJobTokenScopeEnabled: &disabled,
		MaxPersonalAccessTokenLifetime:       &lifetime,
	})

	assert.Equal(t, true, args["allowRunnerRegistrationToken"].Value)
	assert.Equal(t, false, args["enforceCiInboundJobTokenScopeEnabled"].Value)
	assert.Equal(t, int64(30), args["maxPersonalAccessTokenLifetime"].Value)
	assert.Nil(t, args["adminMode"].Value, "a neighbouring unreported setting stays null")
}

//
// Project CI/CD policy decoding
//

func TestProjectCIPolicyDecode(t *testing.T) {
	t.Run("attributes present", func(t *testing.T) {
		ci := &projectCIPolicy{}
		require.NoError(t, json.Unmarshal([]byte(`{
			"ci_id_token_sub_claim_components": ["project_path", "ref_type", "ref", "environment"],
			"ci_allow_fork_pipelines_to_run_in_parent_project": true
		}`), ci))

		assert.Equal(t, []string{"project_path", "ref_type", "ref", "environment"}, ci.IDTokenSubClaimComponents)
		require.NotNil(t, ci.AllowForkPipelinesToRunInParent)
		assert.True(t, *ci.AllowForkPipelinesToRunInParent)
	})

	t.Run("attributes withheld from a non-maintainer", func(t *testing.T) {
		// GitLab drops the CI/CD block from the project payload when the token
		// is below Maintainer. Reporting false there would claim the fork
		// pipeline path is closed on a project nobody actually checked.
		ci := &projectCIPolicy{}
		require.NoError(t, json.Unmarshal([]byte(`{"id":7,"name":"web"}`), ci))

		assert.Nil(t, ci.IDTokenSubClaimComponents)
		assert.Nil(t, ci.AllowForkPipelinesToRunInParent)
	})

	t.Run("fork pipelines explicitly disallowed", func(t *testing.T) {
		ci := &projectCIPolicy{}
		require.NoError(t, json.Unmarshal([]byte(`{"ci_allow_fork_pipelines_to_run_in_parent_project": false}`), ci))

		require.NotNil(t, ci.AllowForkPipelinesToRunInParent)
		assert.False(t, *ci.AllowForkPipelinesToRunInParent)
	})
}

//
// Hook token presence
//

func TestDecodeHooksPairsTokenPresenceWithEachHook(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"id":1,"url":"https://one.example.com","token_present":true}`),
		json.RawMessage(`{"id":2,"url":"https://two.example.com","token_present":false}`),
		json.RawMessage(`{"id":3,"url":"https://three.example.com"}`),
	}

	hooks, presence, err := decodeHooks[gitlab.ProjectHook](raw)
	require.NoError(t, err)
	require.Len(t, hooks, 3)
	require.Len(t, presence, 3)

	assert.Equal(t, "https://one.example.com", hooks[0].URL)
	require.NotNil(t, presence[0].TokenPresent)
	assert.True(t, *presence[0].TokenPresent)

	assert.Equal(t, "https://two.example.com", hooks[1].URL)
	require.NotNil(t, presence[1].TokenPresent)
	assert.False(t, *presence[1].TokenPresent, "a hook with no secret token must read false, not null")

	assert.Equal(t, "https://three.example.com", hooks[2].URL)
	assert.Nil(t, presence[2].TokenPresent,
		"an instance that does not report token_present must read null, not 'no token configured'")
}

func TestDecodeHooksKeepsUnreportedRepositoryUpdateEventsNull(t *testing.T) {
	// The group webhook field of this name shipped as a permanent false for
	// exactly this reason, so the system hook version is decoded as a pointer.
	raw := []json.RawMessage{
		json.RawMessage(`{"id":1,"repository_update_events":true}`),
		json.RawMessage(`{"id":2,"repository_update_events":false}`),
		json.RawMessage(`{"id":3}`),
	}

	_, presence, err := decodeHooks[gitlab.Hook](raw)
	require.NoError(t, err)
	require.Len(t, presence, 3)

	require.NotNil(t, presence[0].RepositoryUpdateEvents)
	assert.True(t, *presence[0].RepositoryUpdateEvents)
	require.NotNil(t, presence[1].RepositoryUpdateEvents)
	assert.False(t, *presence[1].RepositoryUpdateEvents)
	assert.Nil(t, presence[2].RepositoryUpdateEvents,
		"a hook tier that does not carry the attribute must read null, not 'trigger switched off'")
}

func TestDecodeHooksWorksForEveryHookTier(t *testing.T) {
	raw := []json.RawMessage{json.RawMessage(`{"id":9,"url":"https://hook.example.com","token_present":true}`)}

	systemHooks, systemPresence, err := decodeHooks[gitlab.Hook](raw)
	require.NoError(t, err)
	require.Len(t, systemHooks, 1)
	assert.EqualValues(t, 9, systemHooks[0].ID)
	require.NotNil(t, systemPresence[0].TokenPresent)
	assert.True(t, *systemPresence[0].TokenPresent)

	groupHooks, groupPresence, err := decodeHooks[gitlab.GroupHook](raw)
	require.NoError(t, err)
	require.Len(t, groupHooks, 1)
	assert.EqualValues(t, 9, groupHooks[0].ID)
	require.NotNil(t, groupPresence[0].TokenPresent)
	assert.True(t, *groupPresence[0].TokenPresent)
}

func TestDecodeHooksRejectsMalformedElements(t *testing.T) {
	_, _, err := decodeHooks[gitlab.ProjectHook]([]json.RawMessage{json.RawMessage(`{"id":`)})
	assert.Error(t, err)
}

//
// OAuth application redirect URIs
//

func TestSplitRedirectURIs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		callback string
		expected []any
	}{
		{"single uri", "https://app.example.com/callback", []any{"https://app.example.com/callback"}},
		{
			"several uris",
			"https://app.example.com/callback\nhttps://staging.example.com/callback",
			[]any{"https://app.example.com/callback", "https://staging.example.com/callback"},
		},
		{
			"carriage returns and blank lines",
			"https://app.example.com/callback\r\n\r\nhttps://other.example.com/cb\r\n",
			[]any{"https://app.example.com/callback", "https://other.example.com/cb"},
		},
		{"surrounding whitespace", "  https://app.example.com/callback  ", []any{"https://app.example.com/callback"}},
		{"no callback configured", "", []any{}},
		{"only whitespace", "\n  \n", []any{}},
		{"wildcard entry is reported verbatim", "https://*.example.com/cb", []any{"https://*.example.com/cb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, splitRedirectURIs(tc.callback))
		})
	}
}

//
// Not-available versus failed classifier
//

func TestIsTierOrPermissionGated(t *testing.T) {
	statusResponse := func(code int) *gitlab.Response {
		return &gitlab.Response{Response: &http.Response{StatusCode: code}}
	}

	for _, code := range []int{401, 403, 404} {
		assert.True(t, isTierOrPermissionGated(statusResponse(code)),
			"%d means the caller cannot see the data, which is not a scan failure", code)
	}

	for _, code := range []int{200, 400, 409, 429, 500, 502, 503} {
		assert.False(t, isTierOrPermissionGated(statusResponse(code)),
			"%d is a real failure and must not degrade to an empty or null result", code)
	}

	assert.False(t, isTierOrPermissionGated(nil),
		"a transport error carries no response and must never be read as 'not permitted'")
}

//
// Pagination
//

func TestNextPage(t *testing.T) {
	resp := func(next int64) *gitlab.Response {
		return &gitlab.Response{Response: &http.Response{StatusCode: 200}, NextPage: next}
	}

	assert.EqualValues(t, 2, nextPage(resp(2), 1), "a page that advances continues the walk")
	assert.EqualValues(t, 0, nextPage(resp(0), 3), "no next page ends the walk")
	assert.EqualValues(t, 0, nextPage(resp(2), 2), "a repeated page number ends the walk")
	assert.EqualValues(t, 0, nextPage(resp(1), 4), "a rewound page number ends the walk")
	assert.EqualValues(t, 0, nextPage(nil, 1), "no response ends the walk")
}

func TestListRawPagesWalksEveryPage(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		if page < 3 {
			w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		}
		fmt.Fprintf(w, `[{"id":%d}]`, page)
	}))

	raw, _, err := listRawPages(client, "hooks", 1)
	require.NoError(t, err)
	require.Len(t, raw, 3)
	assert.JSONEq(t, `{"id":1}`, string(raw[0]))
	assert.JSONEq(t, `{"id":3}`, string(raw[2]))
}

func TestListRawPagesStopsOnAStuckCursor(t *testing.T) {
	// An endpoint that ignores the page parameter and keeps advertising the
	// same next page would otherwise repeat one page until the process dies.
	calls := 0
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-Next-Page", "2")
		fmt.Fprint(w, `[{"id":1}]`)
	}))

	raw, _, err := listRawPages(client, "hooks", 1)
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "the walk must stop once the page number stops advancing")
	assert.Len(t, raw, 2)
}

func TestListRawPagesSurfacesTheResponseOnError(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"403 Forbidden"}`)
	}))

	raw, resp, err := listRawPages(client, "hooks", 1)
	require.Error(t, err)
	assert.Nil(t, raw)
	require.NotNil(t, resp)
	assert.True(t, isTierOrPermissionGated(resp))
}
