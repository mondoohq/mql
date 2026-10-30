// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOktaStr(t *testing.T) {
	s := "value"
	assert.Equal(t, "value", oktaStr(&s))
	assert.Equal(t, "", oktaStr(nil))
}

func TestOktaBool(t *testing.T) {
	b := true
	assert.True(t, oktaBool(&b))
	assert.False(t, oktaBool(nil))
}

// TestOktaUserArgs_FromUser exercises the *okta.User fast path: pointer/Nullable
// fields are dereferenced and the typed profile is flattened to a dict.
func TestOktaUserArgs_FromUser(t *testing.T) {
	const payload = `{
		"id": "00u1abc",
		"status": "ACTIVE",
		"created": "2024-01-02T03:04:05.000Z",
		"activated": "2024-01-03T03:04:05.000Z",
		"transitioningToStatus": "PROVISIONED",
		"type": {"id": "otyp123"},
		"profile": {"firstName": "Jane", "lastName": "Doe", "login": "jane@example.com"},
		"credentials": {"provider": {"type": "OKTA", "name": "OKTA"}}
	}`
	var u okta.User
	require.NoError(t, json.Unmarshal([]byte(payload), &u))

	args, err := oktaUserArgs(&u)
	require.NoError(t, err)

	assert.Equal(t, "00u1abc", args["id"].Value)
	assert.Equal(t, "ACTIVE", args["status"].Value)
	assert.Equal(t, "PROVISIONED", args["transitioningToStatus"].Value)

	profile, ok := args["profile"].Value.(map[string]any)
	require.True(t, ok, "profile should be a dict")
	assert.Equal(t, "Jane", profile["firstName"])
	assert.Equal(t, "jane@example.com", profile["login"])

	created, ok := args["created"].Value.(*time.Time)
	require.True(t, ok, "created should be a *time.Time")
	assert.Equal(t, 2024, created.Year())

	// NullableTime fields must be unwrapped via .Get(), not dropped.
	activated, ok := args["activated"].Value.(*time.Time)
	require.True(t, ok, "activated (NullableTime) should be a *time.Time")
	assert.NotNil(t, activated)

	// The user type is not a schema field; its id reaches userType through the
	// internal cache, so pin that it decodes off the SDK record.
	require.NotNil(t, u.Type)
	assert.Equal(t, "otyp123", oktaStr(u.Type.Id))
}

// TestOktaUserArgs_FromGroupMember exercises the JSON-normalization branch used
// for the non-okta.User user-shaped types (GroupMember, UserGetSingleton).
func TestOktaUserArgs_FromGroupMembership(t *testing.T) {
	const payload = `{
		"id": "00u9zzz",
		"status": "ACTIVE",
		"profile": {"firstName": "Sam", "login": "sam@example.com"}
	}`
	var m okta.User
	require.NoError(t, json.Unmarshal([]byte(payload), &m))

	user, err := oktaUserFromAny(&m)
	require.NoError(t, err)
	args, err := oktaUserArgs(user)
	require.NoError(t, err)

	assert.Equal(t, "00u9zzz", args["id"].Value)
	profile, ok := args["profile"].Value.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Sam", profile["firstName"])
}

// TestOktaApplicationRawDecode verifies that the fields we surface from the
// polymorphic application union decode from the canonical app JSON.
func TestOktaApplicationRawDecode(t *testing.T) {
	const payload = `{
		"id": "0oabc",
		"name": "testorg_app",
		"label": "Test App",
		"status": "ACTIVE",
		"signOnMode": "SAML_2_0",
		"created": "2024-05-06T00:00:00.000Z",
		"features": ["GROUP_PUSH"],
		"settings": {"signOn": {"defaultRelayState": ""}},
		"profile": {"businessName": "acme"},
		"visibility": {"hide": {"iOS": false}}
	}`
	var app oktaApplicationRaw
	require.NoError(t, json.Unmarshal([]byte(payload), &app))

	assert.Equal(t, "0oabc", app.Id)
	assert.Equal(t, "Test App", app.Label)
	assert.Equal(t, "SAML_2_0", app.SignOnMode)
	assert.Equal(t, "ACTIVE", app.Status)
	assert.Equal(t, []string{"GROUP_PUSH"}, app.Features)
	require.NotNil(t, app.Created)
	assert.Contains(t, string(app.Settings), "signOn")
	assert.Contains(t, string(app.Profile), "businessName")
	assert.Contains(t, string(app.Visibility), "hide")
}

// TestOktaAuthenticatorDecode verifies the authenticator settings/provider
// extraction used by the typed accessors (allowedFor, tokenLifetimeInMinutes,
// userVerification, providerType, providerConfiguration).
func TestOktaAuthenticatorDecode(t *testing.T) {
	const payload = `{
		"id": "aut1",
		"key": "okta_verify",
		"name": "Okta Verify",
		"type": "app",
		"status": "ACTIVE",
		"settings": {"allowedFor": "any", "tokenLifetimeInMinutes": 5, "userVerification": "PREFERRED"},
		"provider": {"type": "PUSH", "configuration": {"foo": "bar"}}
	}`
	var raw oktaAuthenticatorRaw
	require.NoError(t, json.Unmarshal([]byte(payload), &raw))
	assert.Equal(t, "okta_verify", raw.Key)
	assert.Equal(t, "app", raw.Type)

	var s oktaAuthenticatorSettings
	require.NoError(t, json.Unmarshal(raw.Settings, &s))
	assert.Equal(t, "any", s.AllowedFor)
	require.NotNil(t, s.TokenLifetimeInMinutes)
	assert.Equal(t, int64(5), *s.TokenLifetimeInMinutes)
	assert.Equal(t, "PREFERRED", s.UserVerification)

	var p oktaAuthenticatorProvider
	require.NoError(t, json.Unmarshal(raw.Provider, &p))
	assert.Equal(t, "PUSH", p.Type)
	assert.Contains(t, string(p.Configuration), "foo")
}

// TestOktaPolicyRuleRawDecode verifies the shared policy-rule decode shape used
// for both the union-typed listing and the raw access-policy-rules fetch.
func TestOktaPolicyRuleRawDecode(t *testing.T) {
	const payload = `{
		"id": "rul1",
		"name": "Catch-all",
		"priority": 1,
		"status": "ACTIVE",
		"system": true,
		"type": "ACCESS_POLICY",
		"actions": {"appSignOn": {"access": "DENY"}},
		"conditions": {"network": {"connection": "ANYWHERE"}}
	}`
	var r oktaPolicyRuleRaw
	require.NoError(t, json.Unmarshal([]byte(payload), &r))

	assert.Equal(t, "rul1", r.Id)
	assert.Equal(t, int64(1), r.Priority)
	require.NotNil(t, r.System)
	assert.True(t, *r.System)
	assert.Contains(t, string(r.Actions), "appSignOn")
	assert.Contains(t, string(r.Conditions), "ANYWHERE")
}

// TestAuthzServerPolicyRawDecode verifies that the authorization-server policy
// scalars (which the SDK keeps only in AdditionalProperties) decode from the
// canonical JSON.
func TestAuthzServerPolicyRawDecode(t *testing.T) {
	const payload = `{
		"id": "pol1",
		"name": "Default Policy",
		"description": "default policy",
		"priority": 1,
		"status": "ACTIVE",
		"system": true,
		"type": "OAUTH_AUTHORIZATION_POLICY",
		"conditions": {"clients": {"include": ["ALL_CLIENTS"]}}
	}`
	var p authzServerPolicyRaw
	require.NoError(t, json.Unmarshal([]byte(payload), &p))

	assert.Equal(t, "pol1", p.Id)
	assert.Equal(t, "Default Policy", p.Name)
	assert.Equal(t, "default policy", p.Description)
	assert.Equal(t, int64(1), p.Priority)
	require.NotNil(t, p.System)
	assert.True(t, *p.System)
	assert.Contains(t, string(p.Conditions), "ALL_CLIENTS")
}

// TestUserFactorRawDecode verifies the user-factor decode preserves the
// per-factorType profile object that the typed SDK union discards.
func TestUserFactorRawDecode(t *testing.T) {
	const payload = `{
		"id": "fac1",
		"factorType": "sms",
		"provider": "OKTA",
		"status": "ACTIVE",
		"created": "2024-01-01T00:00:00.000Z",
		"profile": {"phoneNumber": "+1 555 0100"}
	}`
	var f userFactorRaw
	require.NoError(t, json.Unmarshal([]byte(payload), &f))

	assert.Equal(t, "sms", f.FactorType)
	assert.Equal(t, "OKTA", f.Provider)
	assert.Equal(t, "+1 555 0100", f.Profile["phoneNumber"])
	require.NotNil(t, f.Created)
}

// TestOktaApplicationRawUniversalLogout pins the Universal Logout decode.
//
// These four values decide whether ending an Okta session actually ends the
// application's session. A mistyped tag would read empty on every app, which
// is indistinguishable from an app that does not support Universal Logout at
// all, so the wrong answer would look like a plausible one.
func TestOktaApplicationRawUniversalLogout(t *testing.T) {
	t.Parallel()

	const payload = `{
		"id": "0oa1",
		"label": "Workspace",
		"universalLogout": {
			"status": "ACTIVE",
			"supportType": "FULL",
			"protocol": "OIDC_BACKCHANNEL",
			"identityStack": "google"
		}
	}`

	entry := &oktaApplicationRaw{}
	require.NoError(t, json.Unmarshal([]byte(payload), entry))

	require.NotNil(t, entry.UniversalLogout)
	assert.Equal(t, "ACTIVE", entry.UniversalLogout.Status)
	assert.Equal(t, "FULL", entry.UniversalLogout.SupportType)
	assert.Equal(t, "OIDC_BACKCHANNEL", entry.UniversalLogout.Protocol)
	assert.Equal(t, "google", entry.UniversalLogout.IdentityStack)
}

// TestOktaApplicationRawWithoutUniversalLogout covers an application Okta
// cannot sign the user out of, which omits the block entirely.
func TestOktaApplicationRawWithoutUniversalLogout(t *testing.T) {
	t.Parallel()

	entry := &oktaApplicationRaw{}
	require.NoError(t, json.Unmarshal([]byte(`{"id":"0oa2","label":"Legacy"}`), entry))
	assert.Nil(t, entry.UniversalLogout,
		"an absent block must not decode to a populated one")
}
