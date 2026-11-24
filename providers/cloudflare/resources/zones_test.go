// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestZoneActivatedOn(t *testing.T) {
	var activated, pending zones.Zone
	require.NoError(t, json.Unmarshal([]byte(`{"id": "z1", "activated_on": "2024-09-15T08:30:00Z", "plan": {"name": "Enterprise Website"}}`), &activated))
	require.NoError(t, json.Unmarshal([]byte(`{"id": "z2", "activated_on": null}`), &pending))

	got := zoneActivatedOn(activated)
	require.NotNil(t, got.Value)
	assert.Equal(t, time.Date(2024, 9, 15, 8, 30, 0, 0, time.UTC), got.Value.(*time.Time).UTC())
	assert.Equal(t, "Enterprise Website", activated.Plan.Name)

	assert.Nil(t, zoneActivatedOn(pending).Value, "a zone that was never activated maps to null")
}

func TestUniversalSslEnabled(t *testing.T) {
	path := fmt.Sprintf("/zones/%s/ssl/universal/settings", testZoneID)

	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			env := setupTestEnv(t)
			zone := createTestZone(t, env)
			env.Mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				jsonResponse(w, fmt.Sprintf(`{"success": true, "errors": [], "messages": [], "result": {"enabled": %v}}`, enabled))
			})
			got, err := zone.universalSslEnabled()
			require.NoError(t, err)
			assert.Equal(t, enabled, got)
		})
	}

	t.Run("permission refusal is an error, not false", func(t *testing.T) {
		env := setupTestEnv(t)
		zone := createTestZone(t, env)
		env.Mux.HandleFunc(path, refuse(http.StatusForbidden))
		_, err := zone.universalSslEnabled()
		assert.Error(t, err)
	})

	t.Run("permission refusal names the permission with structured errors", func(t *testing.T) {
		enableStructuredErrors(t)
		env := setupTestEnv(t)
		zone := createTestZone(t, env)
		env.Mux.HandleFunc(path, refuse(http.StatusForbidden))
		_, err := zone.universalSslEnabled()
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
		var e *llx.Error
		require.ErrorAs(t, err, &e)
		assert.Contains(t, e.Permissions, sslReadPermission)
	})
}

// newNamedTestZone creates a zone with the given id and name, owned by the
// given account.
func newNamedTestZone(t *testing.T, env *testEnv, id, name, accountID string) *mqlCloudflareZone {
	t.Helper()
	acc, err := CreateResource(env.Runtime, "cloudflare.zone.account", map[string]*llx.RawData{
		"id":   llx.StringData(accountID),
		"name": llx.StringData("account " + accountID),
	})
	require.NoError(t, err)
	zone, err := CreateResource(env.Runtime, "cloudflare.zone", map[string]*llx.RawData{
		"id":      llx.StringData(id),
		"name":    llx.StringData(name),
		"account": llx.ResourceData(acc, acc.MqlName()),
	})
	require.NoError(t, err)
	return zone.(*mqlCloudflareZone)
}

func TestNormalizeZoneName(t *testing.T) {
	// Synthetic: case, surrounding space and a trailing root dot; no live
	// account was checked.
	assert.Equal(t, "example.com", normalizeZoneName(" Example.COM. "))
	assert.Equal(t, "", normalizeZoneName(""))
}

func TestZonesNamed(t *testing.T) {
	// Synthetic: two listed zones, a duplicate name and a name no listed
	// zone has; no live account was checked.
	env := setupTestEnv(t)
	a := newNamedTestZone(t, env, "zone-a", "a.example", testAccountID)
	b := newNamedTestZone(t, env, "zone-b", "b.example", testAccountID)
	byName := indexZonesByName([]any{a, b})

	got := zonesNamed([]string{"B.example", "missing.example", "a.example.", "b.example"}, byName)
	assert.Equal(t, []any{b, a}, got)
	assert.Empty(t, zonesNamed([]string{"missing.example"}, byName))
}

func TestZoneNamed(t *testing.T) {
	// Synthetic: the same zone name added to two accounts; no live account
	// was checked. The zone owned by the requested account wins regardless of
	// list order, another account's zone is the fallback, and an unknown name
	// resolves to nothing.
	env := setupTestEnv(t)
	other := newNamedTestZone(t, env, "zone-other", "example.org", "other-account")
	own := newNamedTestZone(t, env, "zone-own", "example.org", testAccountID)
	list := []any{other, own}

	assert.Same(t, own, zoneNamed(list, "Example.org", testAccountID))
	assert.Same(t, other, zoneNamed(list, "example.org", "third-account"))
	assert.Nil(t, zoneNamed(list, "example.net", testAccountID))
	assert.Nil(t, zoneNamed(list, "", testAccountID))
}
