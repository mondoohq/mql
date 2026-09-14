// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Admin API leaves archived workspaces out unless the request asks for
// them, so an offboarding review silently sees a short list. Dropping the
// include_archived parameter from ListWorkspaces fails this test.
func TestListWorkspaces_AsksForArchivedWorkspaces(t *testing.T) {
	var seenQueries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQueries = append(seenQueries, r.URL.Query())
		assert.Equal(t, "/v1/organizations/workspaces", r.URL.Path)

		var resp paginatedResponse[AdminWorkspace]
		switch r.URL.Query().Get("after_id") {
		case "":
			resp = paginatedResponse[AdminWorkspace]{
				Data:    []AdminWorkspace{{ID: "wrkspc_live"}},
				HasMore: true,
				LastID:  "wrkspc_live",
			}
		case "wrkspc_live":
			archivedAt := "2026-02-01T00:00:00Z"
			resp = paginatedResponse[AdminWorkspace]{
				Data:   []AdminWorkspace{{ID: "wrkspc_gone", ArchivedAt: &archivedAt}},
				LastID: "wrkspc_gone",
			}
		default:
			t.Fatalf("unexpected after_id cursor %q", r.URL.Query().Get("after_id"))
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	got, err := c.ListWorkspaces(context.Background())
	require.NoError(t, err)

	require.Len(t, got, 2)
	assert.Equal(t, "wrkspc_gone", got[1].ID)
	require.NotNil(t, got[1].ArchivedAt)

	// Both pages carry the filter. A cursor page that dropped it would go
	// back to reporting live workspaces only from page two onwards.
	require.Len(t, seenQueries, 2)
	for i, q := range seenQueries {
		assert.Equal(t, "true", q.Get("include_archived"), "page %d", i)
		assert.Equal(t, "100", q.Get("limit"), "page %d", i)
	}
	assert.Equal(t, "wrkspc_live", seenQueries[1].Get("after_id"))
}

// paginate appends its own parameters to a path that may already carry one.
// Joining with a second "?" instead of "&" leaves the server parsing
// "true?limit=100" as the value of include_archived, which reads as a request
// for live workspaces only.
func TestPaginate_AppendsToPathThatAlreadyHasQuery(t *testing.T) {
	var seenQueries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQueries = append(seenQueries, r.URL.Query())

		var resp paginatedResponse[item]
		if r.URL.Query().Get("after_id") == "" {
			resp = paginatedResponse[item]{Data: []item{{"a"}}, HasMore: true, LastID: "a"}
		} else {
			resp = paginatedResponse[item]{Data: []item{{"b"}}, LastID: "b"}
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	_, err := paginate[item](context.Background(), c, "/v1/things?flavor=vanilla")
	require.NoError(t, err)

	require.Len(t, seenQueries, 2)
	assert.Equal(t, "vanilla", seenQueries[0].Get("flavor"))
	assert.Equal(t, "100", seenQueries[0].Get("limit"))
	assert.Equal(t, "vanilla", seenQueries[1].Get("flavor"))
	assert.Equal(t, "100", seenQueries[1].Get("limit"))
	assert.Equal(t, "a", seenQueries[1].Get("after_id"))
}

// A cursor carrying characters that are special in a query string has to
// arrive intact. Concatenating it unescaped would truncate it at the first
// "&" and restart the walk from an earlier page.
func TestWithQuery_EscapesValues(t *testing.T) {
	assert.Equal(t, "/p?a=1", withQuery("/p", "a", "1"))
	assert.Equal(t, "/p?a=1&b=2", withQuery("/p?a=1", "b", "2"))
	assert.Equal(t, "/p?after_id=x%26limit%3D1", withQuery("/p", "after_id", "x&limit=1"))
}
