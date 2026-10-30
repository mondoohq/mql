// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListOpenWhiskActions_Paginates verifies the hand-rolled OpenWhisk
// pagination loop follows the limit/skip cursor across pages instead of
// stopping after the first. The endpoint returns a full page (200) then a
// short page (3), so a correct loop yields 203 actions; a truncating loop
// would return only the first 200.
func TestListOpenWhiskActions_Paginates(t *testing.T) {
	const fullPage = 200
	const tail = 3

	var seenSkips []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/namespaces/_/actions", r.URL.Path)
		// basic auth must be forwarded
		u, p, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, "uuid-1", u)
		assert.Equal(t, "key-1", p)

		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		assert.Equal(t, fullPage, limit)
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
		seenSkips = append(seenSkips, skip)

		count := 0
		switch skip {
		case 0:
			count = fullPage
		case fullPage:
			count = tail
		default:
			t.Fatalf("unexpected skip %d — loop paged too far", skip)
		}

		page := make([]owAction, count)
		for i := range page {
			page[i] = owAction{Name: fmt.Sprintf("action-%d", skip+i)}
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(page))
	}))
	defer srv.Close()

	actions, err := listOpenWhiskActions(context.Background(), srv.URL, "uuid-1", "key-1")
	require.NoError(t, err)
	assert.Len(t, actions, fullPage+tail, "all pages should be aggregated")
	assert.Equal(t, []int{0, fullPage}, seenSkips, "skip should advance by the page size")
	// spot-check that later-page actions actually made it in
	assert.Equal(t, "action-0", actions[0].Name)
	assert.Equal(t, fmt.Sprintf("action-%d", fullPage+tail-1), actions[len(actions)-1].Name)
}

// TestListOpenWhiskActions_SinglePage confirms a short first page ends the
// loop immediately (no spurious second request).
func TestListOpenWhiskActions_SinglePage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		page := []owAction{{Name: "only"}}
		require.NoError(t, json.NewEncoder(w).Encode(page))
	}))
	defer srv.Close()

	actions, err := listOpenWhiskActions(context.Background(), srv.URL, "u", "k")
	require.NoError(t, err)
	assert.Len(t, actions, 1)
	assert.Equal(t, 1, calls, "a short first page must not trigger a second request")
}

// TestListOpenWhiskActions_ErrorStatus confirms a non-200 status surfaces as
// an error rather than being decoded as an empty action list.
func TestListOpenWhiskActions_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := listOpenWhiskActions(context.Background(), srv.URL, "u", "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}
