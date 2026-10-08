// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// searchServer serves Global Search pages in order and records the cursor
// each request sent.
func searchServer(t *testing.T, pages []map[string]any, cursors *[]string) *globalsearchv2.GlobalSearchV2 {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SearchCursor string `json:"search_cursor"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		*cursors = append(*cursors, body.SearchCursor)
		require.Less(t, n, len(pages), "more requests than pages")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pages[n])
		n++
	}))
	t.Cleanup(srv.Close)
	gs, err := globalsearchv2.NewGlobalSearchV2(&globalsearchv2.GlobalSearchV2Options{
		URL:           srv.URL,
		Authenticator: &core.NoAuthAuthenticator{},
	})
	require.NoError(t, err)
	return gs
}

func pager(gs *globalsearchv2.GlobalSearchV2) func(*string) (*globalsearchv2.ScanResult, error) {
	return func(cursor *string) (*globalsearchv2.ScanResult, error) {
		res, _, err := gs.Search(&globalsearchv2.SearchOptions{SearchCursor: cursor, Limit: core.Int64Ptr(searchPageSize)})
		return res, err
	}
}

func fullPage(prefix, cursor string) map[string]any {
	items := make([]map[string]any, searchPageSize)
	for i := range items {
		items[i] = map[string]any{"crn": prefix + strconv.Itoa(i)}
	}
	return map[string]any{"search_cursor": cursor, "limit": searchPageSize, "items": items}
}

func TestSearchTagsDecodesTags(t *testing.T) {
	var cursors []string
	gs := searchServer(t, []map[string]any{{
		"search_cursor": "c1", "limit": searchPageSize,
		"items": []map[string]any{
			{"crn": "crn:a", "tags": []string{"env:prod", "team"}, "access_tags": []string{"project:x"}},
			{"crn": "crn:b"},
		},
	}}, &cursors)

	idx, err := searchTags(pager(gs))
	require.NoError(t, err)
	assert.Equal(t, []string{"env:prod", "team"}, idx["crn:a"].user)
	assert.Equal(t, []string{"project:x"}, idx["crn:a"].access)
	assert.Equal(t, []string{"env:prod", "team", "project:x"}, idx["crn:a"].all())
	assert.Empty(t, idx["crn:b"].user, "an untagged resource has no tags")
	assert.Len(t, cursors, 1, "a short page is the last one")
}

func TestSearchTagsFollowsCursor(t *testing.T) {
	var cursors []string
	gs := searchServer(t, []map[string]any{
		fullPage("crn:p1-", "c1"),
		{"search_cursor": "c2", "limit": searchPageSize, "items": []map[string]any{{"crn": "crn:last", "tags": []string{"x"}}}},
	}, &cursors)

	idx, err := searchTags(pager(gs))
	require.NoError(t, err)
	assert.Len(t, idx, searchPageSize+1)
	assert.Equal(t, []string{"x"}, idx["crn:last"].user)
	assert.Equal(t, []string{"", "c1"}, cursors, "the second request carries the first page's cursor")
}

func TestSearchTagsStuckCursor(t *testing.T) {
	var cursors []string
	gs := searchServer(t, []map[string]any{
		fullPage("crn:p1-", "same"),
		fullPage("crn:p2-", "same"),
	}, &cursors)

	_, err := searchTags(pager(gs))
	assert.Error(t, err)
}

func TestAnyStrings(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, anyStrings([]any{"a", 1, "b"}))
	assert.Nil(t, anyStrings(nil))
	assert.Nil(t, anyStrings("a"))
}
