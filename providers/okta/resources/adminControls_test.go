// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/resources/sdk"
	"go.mondoo.com/mql/types"
)

// Okta answers a feature the org is not licensed for with a 401 carrying
// E0000015, which is the same status a dead token gets. Only the code in the
// body tells them apart, and degrading the wrong one reports an unusable
// credential as a clean, empty scan.
func TestIsOktaRawFeatureUnavailable_ErrorCodes(t *testing.T) {
	t.Parallel()

	rawErr := func(status int, body string) error {
		return &sdk.APIError{
			URL:        "https://test.okta.com/api/v1/policies",
			Status:     http.StatusText(status),
			StatusCode: status,
			Code:       oktaErrorCodeFromBody(body),
			Body:       []byte(body),
		}
	}

	t.Run("401 E0000015 is an unlicensed feature", func(t *testing.T) {
		err := rawErr(http.StatusUnauthorized, oktaFeatureNotEnabledBody)
		assert.True(t, isOktaRawFeatureUnavailable(nil, err))
		assert.True(t, isOktaRawFeatureUnavailable(httpResponse(http.StatusUnauthorized), err))
	})

	t.Run("401 E0000011 stays an error", func(t *testing.T) {
		err := rawErr(http.StatusUnauthorized, oktaInvalidTokenBody)
		assert.False(t, isOktaRawFeatureUnavailable(nil, err))
		assert.False(t, isOktaRawFeatureUnavailable(httpResponse(http.StatusUnauthorized), err))
	})

	t.Run("a bare 401 with no code stays an error", func(t *testing.T) {
		err := rawErr(http.StatusUnauthorized, `{"errorSummary":"nope"}`)
		assert.False(t, isOktaRawFeatureUnavailable(httpResponse(http.StatusUnauthorized), err))
	})

	t.Run("a transport error is not a feature verdict", func(t *testing.T) {
		assert.False(t, isOktaRawFeatureUnavailable(nil, errors.New("dial tcp: connection refused")))
	})

	t.Run("the status is read from the error when no response was kept", func(t *testing.T) {
		assert.True(t, isOktaRawFeatureUnavailable(nil, rawErr(http.StatusNotFound, `{}`)))
		assert.False(t, isOktaRawFeatureUnavailable(nil, rawErr(http.StatusInternalServerError, `{}`)))
	})
}

// oktaErrorCodeFromBody mirrors what sdk.newAPIError does when it builds the
// error, so the fixtures above carry the code the real path would carry.
func oktaErrorCodeFromBody(body string) string {
	var decoded struct {
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal([]byte(body), &decoded) != nil {
		return ""
	}
	return decoded.ErrorCode
}

// A policy mapping's resource ids are not declared by the generated model, so
// they arrive in AdditionalProperties. A missed read would report every
// mapping as an empty binding, and "this access policy governs no
// application" would then pass on a policy that governs several.
func TestOktaPolicyMappingFields(t *testing.T) {
	t.Parallel()

	decode := func(t *testing.T, payload string) *okta.PolicyMapping {
		t.Helper()
		var m okta.PolicyMapping
		require.NoError(t, json.Unmarshal([]byte(payload), &m))
		return &m
	}

	t.Run("reads the resource fields and the application id", func(t *testing.T) {
		m := decode(t, `{
			"id": "rsp0000000001",
			"status": "ACTIVE",
			"resourceId": "0oa0000000001",
			"resourceType": "APP",
			"_links": {
				"application": {"href": "https://test.okta.com/api/v1/apps/0oa0000000001"},
				"policy": {"href": "https://test.okta.com/api/v1/policies/rst0000000001"}
			}
		}`)

		resourceType, resourceID, status, appID := oktaPolicyMappingFields(m)
		assert.Equal(t, "APP", resourceType)
		assert.Equal(t, "0oa0000000001", resourceID)
		assert.Equal(t, "ACTIVE", status)
		assert.Equal(t, "0oa0000000001", appID)
		assert.Equal(t, "rsp0000000001", oktaStr(m.Id))
	})

	t.Run("falls back to the HAL link when the resource fields are absent", func(t *testing.T) {
		m := decode(t, `{
			"id": "rsp0000000002",
			"_links": {"application": {"href": "https://test.okta.com/api/v1/apps/0oa0000000002"}}
		}`)

		_, resourceID, _, appID := oktaPolicyMappingFields(m)
		assert.Equal(t, "", resourceID)
		assert.Equal(t, "0oa0000000002", appID)
	})

	t.Run("a binding of another kind does not resolve to an application", func(t *testing.T) {
		m := decode(t, `{
			"id": "rsp0000000003",
			"resourceId": "grp0000000001",
			"resourceType": "GROUP",
			"_links": {"application": {"href": "https://test.okta.com/api/v1/apps/0oa0000000003"}}
		}`)

		resourceType, resourceID, _, appID := oktaPolicyMappingFields(m)
		assert.Equal(t, "GROUP", resourceType)
		assert.Equal(t, "grp0000000001", resourceID)
		assert.Equal(t, "", appID, "a group binding must not be reported as an application")
	})

	t.Run("a mapping with nothing in it yields nothing", func(t *testing.T) {
		m := decode(t, `{"id": "rsp0000000004"}`)
		resourceType, resourceID, status, appID := oktaPolicyMappingFields(m)
		assert.Equal(t, "", resourceType)
		assert.Equal(t, "", resourceID)
		assert.Equal(t, "", status)
		assert.Equal(t, "", appID)
	})
}

// oktaSupportEnabled is super-admin-equivalent: it says whether Okta Support
// staff hold administrator access right now. A status this code does not
// recognize must not be read as "no access", which is the answer a check hopes
// for and would let it pass on a live grant.
func TestOktaSupportEnabledFrom(t *testing.T) {
	t.Parallel()

	str := func(s string) *string { return &s }

	tests := []struct {
		name    string
		support *string
		enabled bool
		known   bool
	}{
		{name: "ENABLED is a live grant", support: str("ENABLED"), enabled: true, known: true},
		{name: "DISABLED is no grant", support: str("DISABLED"), enabled: false, known: true},
		{name: "case is not significant", support: str("enabled"), enabled: true, known: true},
		{name: "an absent status is unknown", support: nil, known: false},
		{name: "an empty status is unknown", support: str(""), known: false},
		{name: "an unrecognized status is unknown", support: str("EXPIRED"), known: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enabled, known := oktaSupportEnabledFrom(tc.support)
			assert.Equal(t, tc.known, known)
			if tc.known {
				assert.Equal(t, tc.enabled, enabled)
			}
		})
	}
}

// The Okta Support settings response is what the three organization fields are
// read out of, so pin that each one survives the SDK's decode.
func TestOktaSupportSettingsDecode(t *testing.T) {
	t.Parallel()

	const payload = `{
		"support": "ENABLED",
		"expiration": "2026-01-24T11:13:14.000Z",
		"caseNumber": "00000000"
	}`
	var settings okta.OrgOktaSupportSettingsObj
	require.NoError(t, json.Unmarshal([]byte(payload), &settings))

	enabled, known := oktaSupportEnabledFrom(settings.Support)
	assert.True(t, known)
	assert.True(t, enabled)

	require.NotNil(t, settings.Expiration.Get())
	assert.Equal(t, 2026, settings.Expiration.Get().Year())
	require.NotNil(t, settings.CaseNumber.Get())
	assert.Equal(t, "00000000", *settings.CaseNumber.Get())

	t.Run("a response without a grant leaves the timestamp absent", func(t *testing.T) {
		var off okta.OrgOktaSupportSettingsObj
		require.NoError(t, json.Unmarshal([]byte(`{"support":"DISABLED"}`), &off))

		enabled, known := oktaSupportEnabledFrom(off.Support)
		assert.True(t, known)
		assert.False(t, enabled)
		assert.Nil(t, off.Expiration.Get(), "an absent expiration must stay null, not become the zero time")
		assert.Nil(t, off.CaseNumber.Get())
	})
}

// The admin-privilege settings are single booleans, and each has a safe
// reading only when the API actually reported it.
func TestOrgAdminPrivilegeSettingsDecode(t *testing.T) {
	t.Parallel()

	var clientPrivileges okta.ClientPrivilegesSetting
	require.NoError(t, json.Unmarshal([]byte(`{"clientPrivilegesSetting": true}`), &clientPrivileges))
	require.NotNil(t, clientPrivileges.ClientPrivilegesSetting)
	assert.True(t, *clientPrivileges.ClientPrivilegesSetting)

	var thirdParty okta.ThirdPartyAdminSetting
	require.NoError(t, json.Unmarshal([]byte(`{"thirdPartyAdmin": true}`), &thirdParty))
	require.NotNil(t, thirdParty.ThirdPartyAdmin)
	assert.True(t, *thirdParty.ThirdPartyAdmin)

	t.Run("an omitted setting stays a nil pointer", func(t *testing.T) {
		var empty okta.ClientPrivilegesSetting
		require.NoError(t, json.Unmarshal([]byte(`{}`), &empty))
		assert.Nil(t, empty.ClientPrivilegesSetting, "an unreported setting must reach the field as null")
	})
}

// The CAPTCHA instance response carries the provider's secret key. It must
// never reach a field, and neither must the site key.
func TestOktaCaptchaArgsCarriesNoKeyMaterial(t *testing.T) {
	t.Parallel()

	const payload = `{
		"id": "cap000000000000",
		"name": "org captcha",
		"type": "HCAPTCHA",
		"siteKey": "site-key-placeholder",
		"secretKey": "secret-key-placeholder"
	}`
	var instance okta.CAPTCHAInstance
	require.NoError(t, json.Unmarshal([]byte(payload), &instance))
	require.NotNil(t, instance.SecretKey, "the fixture must carry a secret for the sweep to mean anything")

	args := oktaCaptchaArgs(&instance)
	assert.Equal(t, "cap000000000000", args["id"].Value)
	assert.Equal(t, "org captcha", args["name"].Value)
	assert.Equal(t, "HCAPTCHA", args["type"].Value)

	assert.ElementsMatch(t, []string{"id", "name", "type"}, mapKeys(args))
	for key, arg := range args {
		value, _ := arg.Value.(string)
		assert.NotContains(t, value, "secret-key-placeholder", "field %q exposes the CAPTCHA secret key", key)
		assert.NotContains(t, value, "site-key-placeholder", "field %q exposes the CAPTCHA site key", key)
	}
}

func mapKeys(m map[string]*llx.RawData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// The org-wide CAPTCHA binding is what says whether any page is protected.
func TestOrgCaptchaSettingsDecode(t *testing.T) {
	t.Parallel()

	var settings okta.OrgCAPTCHASettings
	require.NoError(t, json.Unmarshal([]byte(`{
		"captchaId": "cap000000000000",
		"enabledPages": ["SSR", "SIGN_IN"]
	}`), &settings))

	assert.Equal(t, "cap000000000000", oktaStr(settings.CaptchaId))
	assert.Equal(t, []string{"SSR", "SIGN_IN"}, settings.EnabledPages)

	t.Run("an org with no CAPTCHA reports no instance", func(t *testing.T) {
		var none okta.OrgCAPTCHASettings
		require.NoError(t, json.Unmarshal([]byte(`{"captchaId": null, "enabledPages": []}`), &none))
		assert.Equal(t, "", oktaStr(none.CaptchaId))
		assert.Empty(t, none.EnabledPages)
	})
}

// Bot protection is the credential-stuffing control. A mode or a covered flow
// read wrong is the difference between protection that blocks and protection
// that only writes a log line.
func TestBotProtectionConfigurationDecode(t *testing.T) {
	t.Parallel()

	var config okta.BotProtectionConfiguration
	require.NoError(t, json.Unmarshal([]byte(`{
		"level": "LOW",
		"mode": "LOG_ONLY",
		"enforcementType": "OKTA_CHALLENGE",
		"supportedFlows": ["SIGN_IN", "SSR", "SSPR"]
	}`), &config))

	assert.Equal(t, "LOW", config.Level)
	assert.Equal(t, "LOG_ONLY", config.Mode)
	require.NotNil(t, config.EnforcementType)
	assert.Equal(t, "OKTA_CHALLENGE", *config.EnforcementType)
	assert.Equal(t, []string{"SIGN_IN", "SSR", "SSPR"}, config.SupportedFlows)

	t.Run("an absent enforcement type stays a nil pointer", func(t *testing.T) {
		var partial okta.BotProtectionConfiguration
		require.NoError(t, json.Unmarshal([]byte(`{"level":"HIGH","mode":"ENFORCED"}`), &partial))
		assert.Nil(t, partial.EnforcementType)
		assert.Empty(t, partial.SupportedFlows, "no covered flow must not be invented")
	})
}

// The Okta Personal block list is a credential-exfiltration control, so an
// empty list and an unread list must stay distinguishable.
func TestPersonalAppsBlockListDecode(t *testing.T) {
	t.Parallel()

	var blockList okta.PersonalAppsBlockList
	require.NoError(t, json.Unmarshal([]byte(`{"domains":["example.com","example.net"]}`), &blockList))
	assert.Equal(t, []string{"example.com", "example.net"}, blockList.Domains)

	t.Run("an org blocking nothing decodes to an empty list", func(t *testing.T) {
		var none okta.PersonalAppsBlockList
		require.NoError(t, json.Unmarshal([]byte(`{"domains":[]}`), &none))
		assert.Empty(t, none.Domains)
	})
}

// Subscriptions are keyed by notification type, so an entry that names none
// would collect under an empty key and overwrite the next one like it.
func TestOktaSubscriptionMap(t *testing.T) {
	t.Parallel()

	var subscriptions []okta.Subscription
	require.NoError(t, json.Unmarshal([]byte(`[
		{"notificationType":"REPORT_SUSPICIOUS_ACTIVITY","status":"subscribed","channels":["email"]},
		{"notificationType":"USER_LOCKED_OUT","status":"unsubscribed","channels":["email"]},
		{"status":"subscribed"}
	]`), &subscriptions))

	result := oktaSubscriptionMap(subscriptions)
	assert.Equal(t, map[string]any{
		"REPORT_SUSPICIOUS_ACTIVITY": "subscribed",
		"USER_LOCKED_OUT":            "unsubscribed",
	}, result)

	t.Run("no subscriptions is an empty map, not a nil one", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, oktaSubscriptionMap(nil))
	})
}

// The subscription endpoint takes a role type for a standard role and a role
// id for a custom one. Sending the wrong one reads another role's
// subscriptions, or none at all.
func TestSubscriptionRoleRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		roleType     string
		customRoleID string
		want         string
	}{
		{name: "a standard role is referenced by its type", roleType: "SUPER_ADMIN", want: "SUPER_ADMIN"},
		{
			name:         "a custom role is referenced by its id",
			roleType:     "CUSTOM",
			customRoleID: "cr0000000000001",
			want:         "cr0000000000001",
		},
		{
			name:         "the longer custom type is recognized too",
			roleType:     "CUSTOM_ROLE",
			customRoleID: "cr0000000000002",
			want:         "cr0000000000002",
		},
		{name: "a custom role with no id has nothing to ask about", roleType: "CUSTOM", want: ""},
		{
			name:         "a standard role ignores a stray custom id",
			roleType:     "READ_ONLY_ADMIN",
			customRoleID: "cr0000000000003",
			want:         "READ_ONLY_ADMIN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role := &mqlOktaRole{Type: plugin.TValue[string]{Data: tc.roleType, State: plugin.StateIsSet}}
			role.cacheCustomRoleID = tc.customRoleID
			assert.Equal(t, tc.want, role.subscriptionRoleRef())
		})
	}
}

// An org that is not licensed for bot protection or for Okta Personal must
// reach the fields as null, not as an empty string or an empty list. An empty
// mode reads as protection that is configured and doing nothing, and an empty
// block list reads as an org that bars no domain from carrying credentials
// out, both of which are answers rather than the absence of one.
func TestUnlicensedSingletonsReportNull(t *testing.T) {
	t.Parallel()

	t.Run("bot protection", func(t *testing.T) {
		res := &mqlOktaBotProtection{}
		require.NoError(t, SetAllData(res, map[string]*llx.RawData{
			"__id":            llx.StringData("okta.botProtection"),
			"mode":            llx.NilData,
			"level":           llx.NilData,
			"enforcementType": llx.NilData,
			"supportedFlows":  llx.NilData,
		}))

		for name, field := range map[string]bool{
			"mode":            res.Mode.IsNull(),
			"level":           res.Level.IsNull(),
			"enforcementType": res.EnforcementType.IsNull(),
		} {
			assert.True(t, field, "%s should be null", name)
		}
		assert.True(t, res.SupportedFlows.IsNull(), "supportedFlows should be null, not an empty list")
		assert.True(t, res.Mode.IsSet(), "a null field is still resolved")
	})

	t.Run("okta personal settings", func(t *testing.T) {
		res := &mqlOktaPersonalSettings{}
		require.NoError(t, SetAllData(res, map[string]*llx.RawData{
			"__id":                llx.StringData("okta.personalSettings"),
			"blockedEmailDomains": llx.NilData,
		}))

		assert.True(t, res.BlockedEmailDomains.IsSet())
		assert.True(t, res.BlockedEmailDomains.IsNull(), "an unread block list must not read as blocking nothing")
	})

	t.Run("a licensed org reports the values it holds", func(t *testing.T) {
		res := &mqlOktaBotProtection{}
		require.NoError(t, SetAllData(res, map[string]*llx.RawData{
			"__id":            llx.StringData("okta.botProtection"),
			"mode":            llx.StringData("LOG_ONLY"),
			"level":           llx.StringData("LOW"),
			"enforcementType": llx.StringData("OKTA_CHALLENGE"),
			"supportedFlows":  llx.ArrayData([]any{"SIGN_IN"}, types.String),
		}))

		assert.False(t, res.Mode.IsNull())
		assert.Equal(t, "LOG_ONLY", res.Mode.Data)
		assert.Equal(t, []any{"SIGN_IN"}, res.SupportedFlows.Data)
	})
}
