// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func newTestRoot(t *testing.T, env *testEnv) *mqlCloudflare {
	t.Helper()
	r, err := CreateResource(env.Runtime, "cloudflare", map[string]*llx.RawData{})
	require.NoError(t, err)
	return r.(*mqlCloudflare)
}

func TestZones(t *testing.T) {
	env := setupTestEnv(t)
	root := newTestRoot(t, env)

	env.Mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		// cloudflare-go keeps fetching pages until result is empty (it
		// ignores total_pages). Return empty for any page beyond 1.
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("zones"))
	})

	result, err := root.zones()
	require.NoError(t, err)
	require.Len(t, result, 2)

	z1 := result[0].(*mqlCloudflareZone)
	assert.Equal(t, "d56084adb405e0b7e32c52321bf07be6", z1.Id.Data)
	assert.Equal(t, "example.com", z1.Name.Data)
	assert.Equal(t, "active", z1.Status.Data)
	assert.False(t, z1.Paused.Data)
	assert.Equal(t, "full", z1.Type.Data)
	require.NotNil(t, z1.NameServers.Data)
	assert.Equal(t, []any{"ns1.example.com", "ns2.example.com"}, z1.NameServers.Data)
	assert.Equal(t, []any{"ns-old.registrar.example.net"}, z1.OriginalNameServers.Data)

	require.NotNil(t, z1.Account.Data)
	assert.Equal(t, "01a7362d577a6c3019a474fd6f485823", z1.Account.Data.Id.Data)
	assert.Equal(t, "Test Account", z1.Account.Data.Name.Data)

	require.NotNil(t, z1.Owner.Data)
	assert.Equal(t, "owner-001", z1.Owner.Data.Id.Data)
	assert.Equal(t, "user", z1.Owner.Data.OwnerType.Data)

	z2 := result[1].(*mqlCloudflareZone)
	assert.Equal(t, "abcdef1234567890abcdef1234567890", z2.Id.Data)
	assert.Equal(t, "internal.test", z2.Name.Data)
	assert.Equal(t, "pending", z2.Status.Data)
	assert.Equal(t, "partial", z2.Type.Data)
	assert.Empty(t, z2.NameServers.Data)
}

func TestAccounts(t *testing.T) {
	env := setupTestEnv(t)
	root := newTestRoot(t, env)

	env.Mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("accounts"))
	})

	result, err := root.accounts()
	require.NoError(t, err)
	require.Len(t, result, 2)

	a1 := result[0].(*mqlCloudflareAccount)
	assert.Equal(t, "01a7362d577a6c3019a474fd6f485823", a1.Id.Data)
	assert.Equal(t, "Test Account", a1.Name.Data)
	assert.Equal(t, "standard", a1.Type.Data)

	require.NotNil(t, a1.Settings.Data)
	assert.False(t, a1.Settings.Data.EnforceTwoFactor.Data)

	a2 := result[1].(*mqlCloudflareAccount)
	assert.Equal(t, "9d4e6c8f0a2b1d3f5e7c9b1a8f6e4d2c", a2.Id.Data)
	assert.Equal(t, "enterprise", a2.Type.Data)
	assert.True(t, a2.Settings.Data.EnforceTwoFactor.Data)
}

// TestAccountsPagination guards against the infinite-loop bug where the
// accounts cursor was never advanced and HasMorePages stayed true forever.
// It also asserts every page is consumed (not just the first one).
func TestAccountsPagination(t *testing.T) {
	env := setupTestEnv(t)
	root := newTestRoot(t, env)

	const totalPages = 3
	var calls atomic.Int32

	env.Mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		// Distinct ids per page so we can tell if a page repeats (infinite loop).
		body := fmt.Sprintf(`{
			"success": true, "errors": [], "messages": [],
			"result": [{"id": "acct-p%d", "name": "Account P%d", "type": "standard", "created_on": "2026-01-01T00:00:00Z"}],
			"result_info": {"page": %d, "per_page": 1, "total_pages": %d, "count": 1, "total_count": %d}
		}`, page, page, page, totalPages, totalPages)
		jsonResponse(w, body)
	})

	// If pagination were broken the request handler would loop forever; cap
	// the test with t.Deadline via a goroutine isn't necessary — the previous
	// (buggy) code would re-request page=0 indefinitely. We assert that the
	// handler is called exactly totalPages times.
	result, err := root.accounts()
	require.NoError(t, err)
	require.Len(t, result, totalPages)
	require.Equal(t, int32(totalPages), calls.Load(), "handler should be called once per page, no repeats")

	ids := make([]string, len(result))
	for i, r := range result {
		ids[i] = r.(*mqlCloudflareAccount).Id.Data
	}
	assert.Equal(t, []string{"acct-p1", "acct-p2", "acct-p3"}, ids)
}

// TestAccountsNilSettings asserts that an account whose `settings` field is
// missing from the API response does not panic. The previous code dereferenced
// acc.Settings.EnforceTwoFactor unconditionally.
func TestAccountsNilSettings(t *testing.T) {
	env := setupTestEnv(t)
	root := newTestRoot(t, env)

	env.Mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{
			"success": true, "errors": [], "messages": [],
			"result": [{"id": "no-settings", "name": "No Settings", "type": "standard", "created_on": "2026-01-01T00:00:00Z"}],
			"result_info": {"page": 1, "per_page": 20, "total_pages": 1, "count": 1, "total_count": 1}
		}`)
	})

	result, err := root.accounts()
	require.NoError(t, err)
	require.Len(t, result, 1)

	acc := result[0].(*mqlCloudflareAccount)
	require.NotNil(t, acc.Settings.Data)
	assert.False(t, acc.Settings.Data.EnforceTwoFactor.Data)
}
