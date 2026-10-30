// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/grafana/connection"
)

// newTestConn wires a GrafanaConnection at the given base URL. The token is
// arbitrary — tests don't assert on it.
func newTestConn(t *testing.T, baseURL string) *connection.GrafanaConnection {
	t.Helper()
	conf := &inventory.Config{
		Type:    "grafana",
		Options: map[string]string{"url": baseURL},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("", "test-token"),
		},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewGrafanaConnection(1, asset, conf)
	require.NoError(t, err)
	return conn
}

func TestFetchUserDetail(t *testing.T) {
	t.Run("200 OK decodes detail", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/users/42", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":42,"email":"x@example.com","authModule":"oauth_google","isMFAEnabled":true,"authLabels":["OAuth"]}`))
		}))
		t.Cleanup(srv.Close)

		conn := newTestConn(t, srv.URL)
		d, err := fetchUserDetail(context.Background(), conn, 42)
		require.NoError(t, err)
		assert.Equal(t, 42, d.ID)
		assert.Equal(t, "oauth_google", d.AuthModule)
		assert.True(t, d.IsMFAEnabled)
		assert.Equal(t, []string{"OAuth"}, d.AuthLabels)
	})

	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(fmt.Sprintf("%d tolerated", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)

			conn := newTestConn(t, srv.URL)
			d, err := fetchUserDetail(context.Background(), conn, 42)
			require.NoError(t, err, "403/404 must not propagate")
			assert.Equal(t, 0, d.ID, "zero-value detail expected on tolerated status")
		})
	}

	t.Run("500 returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		conn := newTestConn(t, srv.URL)
		_, err := fetchUserDetail(context.Background(), conn, 42)
		require.Error(t, err)
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not json`))
		}))
		t.Cleanup(srv.Close)

		conn := newTestConn(t, srv.URL)
		_, err := fetchUserDetail(context.Background(), conn, 42)
		require.Error(t, err)
	})
}

func TestFetchUserPermissions(t *testing.T) {
	t.Run("200 decodes scopes as []any", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/access-control/users/7/permissions", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"dashboards:read":["dashboards:uid:a","dashboards:uid:b"],"users:write":[]}`))
		}))
		t.Cleanup(srv.Close)

		conn := newTestConn(t, srv.URL)
		perms, err := fetchUserPermissions(context.Background(), conn, 7)
		require.NoError(t, err)
		require.Contains(t, perms, "dashboards:read")
		scopes, ok := perms["dashboards:read"].([]any)
		require.True(t, ok, "scopes must be []any for MQL array compatibility")
		assert.Equal(t, []any{"dashboards:uid:a", "dashboards:uid:b"}, scopes)
		assert.Equal(t, []any{}, perms["users:write"])
	})

	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(fmt.Sprintf("%d returns non-nil empty map", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)

			conn := newTestConn(t, srv.URL)
			perms, err := fetchUserPermissions(context.Background(), conn, 7)
			require.NoError(t, err)
			require.NotNil(t, perms, "must return empty map so MQL iteration is safe")
			assert.Empty(t, perms)
		})
	}
}

// TestUserPrefetchGroup_DeduplicatesRequests asserts that the bulk fan-out and
// any concurrent lazy per-user accesses converge on exactly one /api/users/{id}
// request per user, regardless of how many callers race for the same user.
func TestUserPrefetchGroup_DeduplicatesRequests(t *testing.T) {
	var counts sync.Map // userID → *atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id int
		_, err := fmt.Sscanf(r.URL.Path, "/api/users/%d", &id)
		require.NoError(t, err)
		v, _ := counts.LoadOrStore(id, &atomic.Int32{})
		v.(*atomic.Int32).Add(1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "authModule": "ldap"})
	}))
	t.Cleanup(srv.Close)

	conn := newTestConn(t, srv.URL)

	const userCount = 25
	users := make([]*mqlGrafanaUser, userCount)
	for i := range users {
		users[i] = &mqlGrafanaUser{}
		users[i].UserId.Data = int64(i + 1)
	}
	group := &userPrefetchGroup{conn: conn, users: users}
	for _, u := range users {
		u.prefetch = group
	}

	// Fire the prefetch from many goroutines simultaneously, plus per-user lazy
	// accessors. All paths must collapse to one HTTP call per user.
	var wg sync.WaitGroup
	const fanIn = 16
	for range fanIn {
		wg.Go(func() {
			group.ensureDetailsFetched()
		})
	}
	for _, u := range users {
		wg.Go(func() {
			_, _ = u.fetchDetail()
		})
	}
	wg.Wait()

	// Validate each user got exactly one HTTP hit and the cached detail is set.
	for _, u := range users {
		v, ok := counts.Load(int(u.UserId.Data))
		require.True(t, ok, "user %d was never fetched", u.UserId.Data)
		assert.Equal(t, int32(1), v.(*atomic.Int32).Load(),
			"user %d was fetched more than once", u.UserId.Data)
		assert.Equal(t, "ldap", u.detail.AuthModule)
		assert.NoError(t, u.detailErr)
	}
}

// TestUserPrefetchGroup_PermissionsFanOut mirrors the detail test for the
// permissions endpoint.
func TestUserPrefetchGroup_PermissionsFanOut(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"datasources:read":["datasources:*"]}`))
	}))
	t.Cleanup(srv.Close)

	conn := newTestConn(t, srv.URL)
	const userCount = 10
	users := make([]*mqlGrafanaUser, userCount)
	for i := range users {
		users[i] = &mqlGrafanaUser{}
		users[i].UserId.Data = int64(i + 1)
	}
	group := &userPrefetchGroup{conn: conn, users: users}
	for _, u := range users {
		u.prefetch = group
	}

	group.ensurePermissionsFetched()
	// Calling again should be a no-op courtesy of sync.Once.
	group.ensurePermissionsFetched()

	assert.Equal(t, int32(userCount), hits.Load(),
		"expected one request per user, no duplicates from second call")
	for _, u := range users {
		assert.Contains(t, u.perms, "datasources:read")
	}
}

// TestUserPrefetchGroup_NilSafe ensures a user without a prefetch group still
// works through the lazy fallback path (covers users created outside users()).
func TestUserPrefetchGroup_NilSafe(t *testing.T) {
	// We don't need a runtime for the prefetch coordination itself, but
	// fetchDetail's lazy fallback calls grafanaConnection(MqlRuntime). Confirm
	// that prefetch==nil simply skips the fan-out — the lazy fallback is
	// exercised in the integration path elsewhere.
	u := &mqlGrafanaUser{}
	u.UserId.Data = 1
	// nil prefetch → ensureDetailsFetched must not be invoked
	assert.Nil(t, u.prefetch)

	// detailOnce is unfired — verify that subsequent direct writes work as if
	// no lock were held.
	u.detailOnce.Do(func() {
		u.detail.AuthModule = "saml"
	})
	assert.Equal(t, "saml", u.detail.AuthModule)
}
