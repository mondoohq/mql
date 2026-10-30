// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZoneIPAccessRules(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/firewall/access_rules/rules", testZoneID), pagedFixture("ip_access_rules"))

	result, err := zone.ipAccessRules()
	require.NoError(t, err)
	require.Len(t, result, 5)

	// Each configuration target is a separate variant of a polymorphic union in
	// cloudflare-go; assert every one lands as target + value rather than
	// collapsing to the first variant.
	wantTargets := []struct{ target, value, mode string }{
		{"ip", "203.0.113.10", "whitelist"},
		{"asn", "AS64512", "whitelist"},
		{"ip_range", "198.51.100.0/24", "block"},
		{"country", "XX", "managed_challenge"},
		{"ip6", "2001:db8::1", "whitelist"},
	}
	for i, want := range wantTargets {
		rule := result[i].(*mqlCloudflareIpAccessRule)
		assert.Equal(t, want.target, rule.Target.Data, "target for rule %d", i)
		assert.Equal(t, want.value, rule.Value.Data, "value for rule %d", i)
		assert.Equal(t, want.mode, rule.Mode.Data, "mode for rule %d", i)
	}

	first := result[0].(*mqlCloudflareIpAccessRule)
	assert.Equal(t, "ar-allow-ip", first.Id.Data)
	assert.Equal(t, "office egress", first.Notes.Data)
	assert.Equal(t, "user", first.ScopeType.Data)
	assert.Equal(t, []any{"block", "challenge", "whitelist", "js_challenge", "managed_challenge"}, first.AllowedModes.Data)
	assert.False(t, first.CreatedOn.IsNull())

	// An account-scoped rule inherited into the zone reports its origin.
	assert.Equal(t, "organization", result[1].(*mqlCloudflareIpAccessRule).ScopeType.Data)
}

func TestAccountIPAccessRules_distinctCacheKeyFromZone(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	account := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/firewall/access_rules/rules", testZoneID), pagedFixture("ip_access_rules"))
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/firewall/access_rules/rules", testAccountID), pagedFixture("ip_access_rules"))

	zoneRules, err := zone.ipAccessRules()
	require.NoError(t, err)
	accountRules, err := account.ipAccessRules()
	require.NoError(t, err)
	require.Len(t, zoneRules, 5)
	require.Len(t, accountRules, 5)

	// The same rule id reached through both scopes must not collapse onto one
	// cached resource, or the account listing would alias the zone's.
	assert.NotEqual(t,
		zoneRules[0].(*mqlCloudflareIpAccessRule).__id,
		accountRules[0].(*mqlCloudflareIpAccessRule).__id,
	)
}

func TestZoneIPAccessRules_degradesWhenUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/firewall/access_rules/rules", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"not available"}]}`)
	})

	result, err := zone.ipAccessRules()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestZoneLockdowns(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/firewall/lockdowns", testZoneID), pagedFixture("lockdowns"))

	result, err := zone.lockdowns()
	require.NoError(t, err)
	require.Len(t, result, 2)

	admin := result[0].(*mqlCloudflareZoneLockdown)
	assert.Equal(t, "ld-admin", admin.Id.Data)
	assert.Equal(t, "Pin wp-admin to the office", admin.Description.Data)
	assert.False(t, admin.Paused.Data)
	assert.Equal(t, []any{"example.com/wp-admin*", "example.com/wp-login.php"}, admin.Urls.Data)
	assert.Equal(t, []any{
		map[string]any{"target": "ip", "value": "203.0.113.10"},
		map[string]any{"target": "ip_range", "value": "198.51.100.0/24"},
	}, admin.Configurations.Data)

	// A paused lockdown is defined but enforcing nothing.
	staging := result[1].(*mqlCloudflareZoneLockdown)
	assert.True(t, staging.Paused.Data)
}

func TestZoneHold(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/hold", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("zone_hold"))
	})

	hold, err := zone.hold()
	require.NoError(t, err)
	require.NotNil(t, hold)
	assert.True(t, hold.Enabled.Data)
	assert.Equal(t, "true", hold.IncludeSubdomains.Data)
	assert.False(t, hold.HoldAfter.IsNull())
}

func TestZoneHold_noHoldSet(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/hold", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("zone_hold_absent"))
	})

	hold, err := zone.hold()
	require.NoError(t, err)
	require.NotNil(t, hold)
	assert.False(t, hold.Enabled.Data)
	// An empty hold_after must stay null rather than becoming January 1 year 1.
	assert.True(t, hold.HoldAfter.IsNull())
}

func TestZoneHold_unreadableIsNullNotUnprotected(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/hold", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"not available"}]}`)
	})

	hold, err := zone.hold()
	require.NoError(t, err)
	assert.Nil(t, hold, "an unreadable hold must be null, not a hold reading disabled")
	assert.True(t, zone.Hold.IsNull())
}
