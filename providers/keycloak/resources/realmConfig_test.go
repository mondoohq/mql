// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealmKeysDecode(t *testing.T) {
	// The shape of GET /admin/realms/{realm}/keys.
	const payload = `{
      "keys": [
        {"providerId":"p1","providerPriority":100,"kid":"kid-rsa","status":"ACTIVE","type":"RSA","algorithm":"RS256","use":"SIG","publicKey":"MIIBIj","certificate":"MIICmz"},
        {"providerId":"p2","providerPriority":100,"kid":"kid-old","status":"PASSIVE","type":"RSA","algorithm":"RS256","use":"SIG"},
        {"providerId":"p3","providerPriority":100,"kid":"kid-hs","status":"ACTIVE","type":"OCT","algorithm":"HS256","use":"SIG"},
        {"providerId":"p4","providerPriority":100,"kid":"kid-enc","status":"DISABLED","type":"RSA","algorithm":"RSA-OAEP","use":"ENC"}
      ]
    }`

	var resp realmKeysResponse
	require.NoError(t, json.Unmarshal([]byte(payload), &resp))

	require.Len(t, resp.Keys, 4)
	assert.Equal(t, "kid-rsa", resp.Keys[0].Kid)
	assert.Equal(t, "RS256", resp.Keys[0].Algorithm)
	assert.Equal(t, "SIG", resp.Keys[0].Use)
	assert.Equal(t, int64(100), resp.Keys[0].ProviderPriority)

	// A realm that signs with HS256 shares the signing secret with every
	// client that validates it.
	assert.Equal(t, "HS256", resp.Keys[2].Algorithm)
	assert.True(t, IsActiveKey(resp.Keys[2].Status))

	// Only an active key signs new tokens.
	assert.True(t, IsActiveKey(resp.Keys[0].Status))
	assert.False(t, IsActiveKey(resp.Keys[1].Status))
	assert.False(t, IsActiveKey(resp.Keys[3].Status))
}

func TestIsActiveKey(t *testing.T) {
	assert.True(t, IsActiveKey("ACTIVE"))
	assert.True(t, IsActiveKey("active"))
	assert.True(t, IsActiveKey(" ACTIVE "))
	assert.False(t, IsActiveKey("PASSIVE"))
	assert.False(t, IsActiveKey("DISABLED"))
	assert.False(t, IsActiveKey(""))
}

func TestEventsConfigDecode(t *testing.T) {
	// The shape of GET /admin/realms/{realm}/events/config.
	const payload = `{
      "eventsEnabled": true,
      "eventsExpiration": 604800,
      "eventsListeners": ["jboss-logging"],
      "enabledEventTypes": ["LOGIN","LOGIN_ERROR","LOGOUT","CODE_TO_TOKEN_ERROR"],
      "adminEventsEnabled": false,
      "adminEventsDetailsEnabled": false
    }`

	var rec eventsConfigRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.True(t, rec.EventsEnabled)
	assert.Equal(t, int64(604800), rec.EventsExpiration)
	assert.Equal(t, []string{"jboss-logging"}, rec.EventsListeners)
	assert.Contains(t, rec.EnabledEventTypes, "LOGIN_ERROR")
	// Without admin events, a change to a redirect URI leaves no trace.
	assert.False(t, rec.AdminEventsEnabled)
}

func TestEventsConfigDecodeWithRecordingOff(t *testing.T) {
	const payload = `{"eventsEnabled":false,"eventsListeners":["jboss-logging"],"enabledEventTypes":[],"adminEventsEnabled":false}`

	var rec eventsConfigRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.False(t, rec.EventsEnabled)
	assert.Empty(t, rec.EnabledEventTypes)
	assert.Equal(t, int64(0), rec.EventsExpiration)
}

func TestClientProfilesDecode(t *testing.T) {
	// The realm's own profiles and the ones Keycloak ships arrive in separate
	// lists. A policy may name either, so both are read.
	const payload = `{
      "profiles": [
        {"name":"strict","description":"in-house","executors":[
          {"executor":"pkce-enforcer","configuration":{"auto-configure":true}},
          {"executor":"confidential-client-acceptable","configuration":{}}
        ]}
      ],
      "globalProfiles": [
        {"name":"fapi-1-baseline","description":"builtin","executors":[
          {"executor":"secure-session-enforcer","configuration":{}}
        ]}
      ]
    }`

	var resp clientProfilesResponse
	require.NoError(t, json.Unmarshal([]byte(payload), &resp))

	require.Len(t, resp.Profiles, 1)
	require.Len(t, resp.GlobalProfiles, 1)

	assert.Equal(t, "strict", resp.Profiles[0].Name)
	require.Len(t, resp.Profiles[0].Executors, 2)
	assert.Equal(t, "pkce-enforcer", resp.Profiles[0].Executors[0].Executor)
	assert.Equal(t, true, resp.Profiles[0].Executors[0].Configuration["auto-configure"])
	assert.Equal(t, "confidential-client-acceptable", resp.Profiles[0].Executors[1].Executor)

	assert.Equal(t, "fapi-1-baseline", resp.GlobalProfiles[0].Name)
}

func TestClientPoliciesDecode(t *testing.T) {
	const payload = `{
      "policies": [
        {"name":"enforce-pkce","description":"","enabled":true,"profiles":["strict"],"conditions":[
          {"condition":"client-access-type","configuration":{"type":["public"]}}
        ]},
        {"name":"draft","enabled":false,"profiles":[],"conditions":[]}
      ],
      "globalPolicies": []
    }`

	var resp clientPoliciesResponse
	require.NoError(t, json.Unmarshal([]byte(payload), &resp))

	require.Len(t, resp.Policies, 2)

	assert.Equal(t, "enforce-pkce", resp.Policies[0].Name)
	assert.True(t, resp.Policies[0].Enabled)
	assert.Equal(t, []string{"strict"}, resp.Policies[0].Profiles)
	require.Len(t, resp.Policies[0].Conditions, 1)
	assert.Equal(t, "client-access-type", resp.Policies[0].Conditions[0].Condition)

	// A disabled policy that names no profile enforces nothing.
	assert.False(t, resp.Policies[1].Enabled)
	assert.Empty(t, resp.Policies[1].Profiles)
}

func TestAuthorizationSettingsDecode(t *testing.T) {
	// The shape of GET /clients/{id}/authz/resource-server. With PERMISSIVE, a
	// request for a resource no policy covers is allowed.
	const payload = `{
      "id": "rs-1",
      "clientId": "app",
      "name": "app",
      "allowRemoteResourceManagement": true,
      "policyEnforcementMode": "PERMISSIVE",
      "decisionStrategy": "UNANIMOUS"
    }`

	var rec authorizationSettingsRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "PERMISSIVE", rec.PolicyEnforcementMode)
	assert.Equal(t, "UNANIMOUS", rec.DecisionStrategy)
	assert.True(t, rec.AllowRemoteResourceManagement)
}

func TestAuthorizationSettingsDecodeWhenEnforcing(t *testing.T) {
	const payload = `{"policyEnforcementMode":"ENFORCING","decisionStrategy":"AFFIRMATIVE","allowRemoteResourceManagement":false}`

	var rec authorizationSettingsRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "ENFORCING", rec.PolicyEnforcementMode)
	assert.Equal(t, "AFFIRMATIVE", rec.DecisionStrategy)
	assert.False(t, rec.AllowRemoteResourceManagement)
}

func TestExecutionConfigDecode(t *testing.T) {
	// The settings of a conditional one-time password step, which decide when
	// the second factor is demanded.
	const payload = `{
      "id": "cfg-1",
      "alias": "otp-conditional",
      "config": {"defaultOtpOutcome": "skip", "otpControlAttribute": "user.attribute"}
    }`

	var rec executionConfigRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "otp-conditional", rec.Alias)
	// A step set to skip demands no second factor, which the requirement alone
	// does not reveal.
	assert.Equal(t, "skip", rec.Config["defaultOtpOutcome"])
	assert.Len(t, rec.Config, 2)
}
