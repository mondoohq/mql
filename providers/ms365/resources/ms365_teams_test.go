// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeFederation(t *testing.T, raw string) *CsTenantFederationConfiguration {
	t.Helper()
	report := &MsTeamsReport{}
	require.NoError(t, json.Unmarshal([]byte(raw), report))
	require.NotNil(t, report.CsTenantFederationConfiguration)
	return report.CsTenantFederationConfiguration
}

// Default tenant: AllowedDomains is AllowAllKnownDomains and MicrosoftTeams 8.x
// no longer returns AllowPublicUsers.
func TestTeamsFederation_AllowAllKnownDomains(t *testing.T) {
	cfg := decodeFederation(t, `{"CsTenantFederationConfiguration": {
		"Identity": "Global",
		"AllowedDomains": ["AllowAllKnownDomains"],
		"BlockedDomains": ["blocked.example"],
		"AllowFederatedUsers": true,
		"AllowTeamsConsumer": true
	}}`)

	allowed, allowAll := normalizeFederationDomains(cfg.AllowedDomains)
	assert.True(t, allowAll)
	assert.Empty(t, allowed)

	blocked, blockedAllowAll := normalizeFederationDomains(cfg.BlockedDomains)
	assert.False(t, blockedAllowAll)
	assert.Equal(t, []string{"blocked.example"}, blocked)

	assert.Nil(t, cfg.AllowPublicUsers, "absent AllowPublicUsers must decode as null, not false")
}

// Allow list with domains, as emitted from the AllowList.AllowedDomain entries.
func TestTeamsFederation_AllowList(t *testing.T) {
	cfg := decodeFederation(t, `{"CsTenantFederationConfiguration": {
		"AllowedDomains": ["contoso.com", "fabrikam.com"],
		"BlockedDomains": [],
		"AllowPublicUsers": true
	}}`)

	allowed, allowAll := normalizeFederationDomains(cfg.AllowedDomains)
	assert.False(t, allowAll)
	assert.Equal(t, []string{"contoso.com", "fabrikam.com"}, allowed)

	require.NotNil(t, cfg.AllowPublicUsers)
	assert.True(t, *cfg.AllowPublicUsers)
}

// The AllowList string form the MicrosoftTeams module sets as ToString.
func TestTeamsFederation_AllowListStringForm(t *testing.T) {
	cfg := decodeFederation(t, `{"CsTenantFederationConfiguration": {
		"AllowedDomains": ["Domain=contoso.com,Domain=fabrikam.com"]
	}}`)
	allowed, allowAll := normalizeFederationDomains(cfg.AllowedDomains)
	assert.False(t, allowAll)
	assert.Equal(t, []string{"contoso.com", "fabrikam.com"}, allowed)
}

// An empty allow list (no external domain allowed) and null entries must not
// produce an empty-string domain.
func TestTeamsFederation_EmptyAndNullEntries(t *testing.T) {
	cfg := decodeFederation(t, `{"CsTenantFederationConfiguration": {
		"AllowedDomains": [null, ""],
		"BlockedDomains": null
	}}`)

	allowed, allowAll := normalizeFederationDomains(cfg.AllowedDomains)
	assert.False(t, allowAll)
	assert.Empty(t, allowed)
	assert.NotNil(t, allowed, "an empty list, not null")

	blocked, _ := normalizeFederationDomains(cfg.BlockedDomains)
	assert.Empty(t, blocked)
}

// Get-CsTeamsMeetingPolicy returns neither AllowSecurityEndUserReporting nor
// PreventTollBypass; an absent property must stay null instead of false.
func TestTeamsMeetingPolicy_AbsentPropertiesAreNull(t *testing.T) {
	report := &MsTeamsReport{}
	require.NoError(t, json.Unmarshal([]byte(`{"CsTeamsMeetingPolicy": {
		"AllowAnonymousUsersToJoinMeeting": true,
		"AllowCloudRecordingForCalls": true
	}}`), report))
	require.NotNil(t, report.CsTeamsMeetingPolicy)
	assert.Nil(t, report.CsTeamsMeetingPolicy.AllowSecurityEndUserReporting)
	assert.Nil(t, report.CsTeamsMeetingPolicy.PreventTollBypass)
	assert.True(t, report.CsTeamsMeetingPolicy.AllowCloudRecordingForCalls)
}

// PreventTollBypass is copied from the calling policy onto the meeting policy.
func TestTeamsMeetingPolicy_PreventTollBypassFromCallingPolicy(t *testing.T) {
	report := &MsTeamsReport{}
	require.NoError(t, json.Unmarshal([]byte(`{"CsTeamsMeetingPolicy": {"PreventTollBypass": true}}`), report))
	require.NotNil(t, report.CsTeamsMeetingPolicy.PreventTollBypass)
	assert.True(t, *report.CsTeamsMeetingPolicy.PreventTollBypass)
}
