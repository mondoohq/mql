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

func handlePrecursor(env *testEnv, status int, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/precursor", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		jsonResponse(w, body)
	})
}

// defaultMode decides the posture for every request that matches no rule, so a
// mis-decoded value silently reports a zone as enforcing when it is off.
func TestPrecursorDefaultMode(t *testing.T) {
	for _, mode := range []string{"off", "min-friction", "max-security"} {
		t.Run(mode, func(t *testing.T) {
			env := setupTestEnv(t)
			zone := createTestZone(t, env)
			handlePrecursor(env, http.StatusOK, fmt.Sprintf(
				`{"success":true,"result":{"default_mode":%q,"enforcement_rules":[]}}`, mode))

			p, err := zone.precursor()
			require.NoError(t, err)
			require.NotNil(t, p)
			assert.Equal(t, mode, p.DefaultMode.Data)
			assert.Empty(t, p.EnforcementRules.Data)
		})
	}
}

func TestPrecursorEnforcementRules(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handlePrecursor(env, http.StatusOK, `{"success":true,"result":{
		"default_mode":"min-friction",
		"enforcement_rules":[
			{"id":"rule-a","expression":"http.request.uri.path contains \"/admin\"","mode":"max-security","description":"protect admin","enabled":true},
			{"id":"rule-b","expression":"http.host eq \"api.example.com\"","mode":"min-friction","description":"","enabled":false}
		]}}`)

	p, err := zone.precursor()
	require.NoError(t, err)
	require.Len(t, p.EnforcementRules.Data, 2)

	first := p.EnforcementRules.Data[0].(*mqlCloudflareZonePrecursorEnforcementRule)
	assert.Equal(t, "rule-a", first.Id.Data)
	assert.Equal(t, "max-security", first.Mode.Data)
	assert.Equal(t, "protect admin", first.Description.Data)
	assert.True(t, first.Enabled.Data)
	assert.Contains(t, first.Expression.Data, "/admin")

	// A rule that is present but disabled must not read as enforcing. This is
	// the field that decides whether a rule tightening the posture is inert.
	second := p.EnforcementRules.Data[1].(*mqlCloudflareZonePrecursorEnforcementRule)
	assert.Equal(t, "rule-b", second.Id.Data)
	assert.False(t, second.Enabled.Data)
}

// Two rules arriving without ids must still occupy distinct cache entries.
// Sharing one would make the second report the first's expression and mode,
// which reads as a duplicate rule rather than as an error.
func TestPrecursorRulesWithoutIDsGetDistinctIDs(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handlePrecursor(env, http.StatusOK, `{"success":true,"result":{
		"default_mode":"off",
		"enforcement_rules":[
			{"expression":"http.host eq \"a.example.com\"","mode":"max-security","enabled":true},
			{"expression":"http.host eq \"b.example.com\"","mode":"min-friction","enabled":true}
		]}}`)

	p, err := zone.precursor()
	require.NoError(t, err)
	require.Len(t, p.EnforcementRules.Data, 2)

	first := p.EnforcementRules.Data[0].(*mqlCloudflareZonePrecursorEnforcementRule)
	second := p.EnforcementRules.Data[1].(*mqlCloudflareZonePrecursorEnforcementRule)

	assert.NotEqual(t, first.MqlID(), second.MqlID())
	assert.Contains(t, first.Expression.Data, "a.example.com")
	assert.Contains(t, second.Expression.Data, "b.example.com")
}

// A zone whose plan does not include Precursor answers 403. That must report a
// null resource rather than failing every other check on the zone.
func TestPrecursorUnavailableIsNull(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handlePrecursor(env, http.StatusForbidden,
		`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)

	p, err := zone.precursor()
	require.NoError(t, err)
	assert.Nil(t, p)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, zone.Precursor.State)
}

// Synthetic: the current configuration shape returned under Cloudflare-Version
// 1.0 (cloudflare-go v7.14.0); no zone with Precursor was available.
func TestPrecursorCurrentShape(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handlePrecursor(env, http.StatusOK, `{"success":true,"result":{
		"mode":"monitor","show_interstitial":true,
		"rules":[
			{"id":"r-1","expression":"http.request.uri.path contains \"/login\"","show_interstitial":false,"description":"no interstitial on login","enabled":true},
			{"expression":"http.host eq \"a.example.com\"","show_interstitial":true,"enabled":false},
			{"expression":"http.host eq \"b.example.com\"","show_interstitial":true,"enabled":true}
		]}}`)

	p, err := zone.precursor()
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "monitor", p.Mode.Data)
	assert.True(t, p.ShowInterstitial.Data)
	require.Len(t, p.Rules.Data, 3)

	first := p.Rules.Data[0].(*mqlCloudflareZonePrecursorRule)
	assert.Equal(t, "r-1", first.Id.Data)
	assert.False(t, first.ShowInterstitial.Data)
	assert.Equal(t, "no interstitial on login", first.Description.Data)
	assert.True(t, first.Enabled.Data)

	second := p.Rules.Data[1].(*mqlCloudflareZonePrecursorRule)
	third := p.Rules.Data[2].(*mqlCloudflareZonePrecursorRule)
	assert.True(t, second.Description.IsNull(), "an absent description must read null")
	assert.False(t, second.Enabled.Data)
	assert.NotEqual(t, second.MqlID(), third.MqlID(), "rules without ids must not share a cache entry")
	assert.Contains(t, third.Expression.Data, "b.example.com")

	// The retired fields are not in this shape: null and empty, not "off".
	assert.True(t, p.DefaultMode.IsNull())
	assert.Empty(t, p.EnforcementRules.Data)
}

// Synthetic: a body with no show_interstitial key reports null rather than
// false, which would read as a measured "no interstitial".
func TestPrecursorShowInterstitialAbsentIsNull(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handlePrecursor(env, http.StatusOK, `{"success":true,"result":{"mode":"arm","rules":[]}}`)

	p, err := zone.precursor()
	require.NoError(t, err)
	assert.Equal(t, "arm", p.Mode.Data)
	assert.True(t, p.ShowInterstitial.IsNull())
	assert.Empty(t, p.Rules.Data)
}

func TestDecodePrecursorLegacy(t *testing.T) {
	legacy := decodePrecursorLegacy(`{"default_mode":"max-security","enforcement_rules":[{"id":"x","mode":"min-friction"}]}`)
	require.NotNil(t, legacy.DefaultMode)
	assert.Equal(t, "max-security", *legacy.DefaultMode)
	require.Len(t, legacy.EnforcementRules, 1)
	assert.Equal(t, "min-friction", legacy.EnforcementRules[0].Mode)

	assert.Nil(t, decodePrecursorLegacy(`{"mode":"arm"}`).DefaultMode)
	assert.Nil(t, decodePrecursorLegacy(`not json`).DefaultMode)
	assert.Nil(t, decodePrecursorLegacy("").DefaultMode)
}
