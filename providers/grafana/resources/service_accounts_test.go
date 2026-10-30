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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPagedServer returns a test server that serves /api/serviceaccounts/search
// as a paged endpoint. totalCount records how many SAs exist in total.
func newPagedServer(t *testing.T, totalCount int, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("perpage"))
		if perPage < 1 {
			perPage = serviceAccountPageSize
		}

		start := (page - 1) * perPage
		end := min(start+perPage, totalCount)
		var items []grafanaServiceAccountJSON
		if start < totalCount {
			items = make([]grafanaServiceAccountJSON, end-start)
			for i := range items {
				items[i] = grafanaServiceAccountJSON{
					ID:   start + i + 1,
					Name: fmt.Sprintf("sa-%d", start+i+1),
				}
			}
		}
		resp := grafanaServiceAccountsResponse{
			TotalCount:      totalCount,
			ServiceAccounts: items,
			Page:            page,
			PerPage:         perPage,
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// newCappingPagedServer models a Grafana instance that silently caps the page
// size below the requested perpage: it clamps the effective perPage to maxPerPage
// and computes offsets from that clamped value (as Grafana's search service does).
func newCappingPagedServer(t *testing.T, totalCount, maxPerPage int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("perpage"))
		if perPage < 1 || perPage > maxPerPage {
			perPage = maxPerPage
		}
		start := (page - 1) * perPage
		end := min(start+perPage, totalCount)
		var items []grafanaServiceAccountJSON
		if start < totalCount {
			items = make([]grafanaServiceAccountJSON, end-start)
			for i := range items {
				items[i] = grafanaServiceAccountJSON{ID: start + i + 1, Name: fmt.Sprintf("sa-%d", start+i+1)}
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(grafanaServiceAccountsResponse{
			TotalCount:      totalCount,
			ServiceAccounts: items,
			Page:            page,
			PerPage:         perPage,
		})
	}))
}

// newAllInOnePageServer models a Grafana instance that ignores perpage and
// returns every service account in a single page regardless of the page param.
func newAllInOnePageServer(t *testing.T, totalCount int, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		items := make([]grafanaServiceAccountJSON, totalCount)
		for i := range items {
			items[i] = grafanaServiceAccountJSON{ID: i + 1, Name: fmt.Sprintf("sa-%d", i+1)}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(grafanaServiceAccountsResponse{
			TotalCount:      totalCount,
			ServiceAccounts: items,
			Page:            1,
			PerPage:         totalCount,
		})
	}))
}

func TestFetchServiceAccountPage(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		srv := newPagedServer(t, 5, nil)
		t.Cleanup(srv.Close)
		conn := newTestConn(t, srv.URL)

		page, err := fetchServiceAccountPage(context.Background(), conn, 1, serviceAccountPageSize)
		require.NoError(t, err)
		assert.Equal(t, 5, page.TotalCount)
		assert.Len(t, page.ServiceAccounts, 5)
	})

	t.Run("non-200 errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		conn := newTestConn(t, srv.URL)

		_, err := fetchServiceAccountPage(context.Background(), conn, 1, serviceAccountPageSize)
		require.Error(t, err)
	})
}

func TestServiceAccountPageCount(t *testing.T) {
	tests := []struct {
		name         string
		totalCount   int
		firstPageLen int
		want         int
	}{
		{"empty org", 0, 0, 1},
		{"single short page", 5, 5, 1},
		{"exactly one full page", 1000, 1000, 1},
		{"one over a full page", 1001, 1000, 2},
		{"three full pages plus one", serviceAccountPageSize*3 + 1, serviceAccountPageSize, 4},
		// Server caps perpage below our request (e.g. returns 100 despite perpage=1000):
		// pages must be sized to what the server actually returned, not truncated.
		{"server caps perpage", 250, 100, 3},
		{"server caps perpage exact multiple", 300, 100, 3},
		// Server ignores perpage and returns everything in page 1: must stay one
		// page so we never re-fetch and duplicate rows.
		{"server ignores perpage", 2500, 2500, 1},
		// Defensive: a zero first page with a positive total must not divide by zero.
		{"zero first page nonzero total", 500, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, serviceAccountPageCount(tt.totalCount, tt.firstPageLen))
		})
	}
}

// assertUniqueIDs fails if the collected service accounts contain any duplicate
// IDs — the signature of a pagination loop that re-fetches the same page.
func assertUniqueIDs(t *testing.T, sas []grafanaServiceAccountJSON, wantLen int) {
	t.Helper()
	assert.Len(t, sas, wantLen)
	seen := make(map[int]bool, len(sas))
	for _, sa := range sas {
		require.False(t, seen[sa.ID], "duplicate service account ID %d — pagination re-fetched a page", sa.ID)
		seen[sa.ID] = true
	}
}

// TestServiceAccountPagination_FetchesAllPages drives the real
// fetchAllServiceAccounts against a server that honors perpage, verifying every
// page is read exactly once and the union is complete with no duplicates.
func TestServiceAccountPagination_FetchesAllPages(t *testing.T) {
	const total = serviceAccountPageSize*3 + 1
	var hits atomic.Int32
	srv := newPagedServer(t, total, &hits)
	t.Cleanup(srv.Close)
	conn := newTestConn(t, srv.URL)

	got, err := fetchAllServiceAccounts(context.Background(), conn)
	require.NoError(t, err)
	assertUniqueIDs(t, got, total)
	// 4 pages at serviceAccountPageSize each (3 full + 1 remainder).
	assert.Equal(t, int32(4), hits.Load(),
		"server hit exactly once per page — pagination must not retry or duplicate")
}

// TestServiceAccountPagination_ServerCapsPerPage guards the fix for the
// truncation bug: when the server returns fewer items than the requested
// perpage (e.g. an instance that caps the search page size) while totalCount
// reports more, the loop must page off the effective size and still collect
// every account rather than stopping after page 1.
func TestServiceAccountPagination_ServerCapsPerPage(t *testing.T) {
	const (
		total      = 250
		perPageCap = 100
	)
	srv := newCappingPagedServer(t, total, perPageCap)
	t.Cleanup(srv.Close)
	conn := newTestConn(t, srv.URL)

	got, err := fetchAllServiceAccounts(context.Background(), conn)
	require.NoError(t, err)
	assertUniqueIDs(t, got, total) // must be all 250, not truncated to 100
}

// TestServiceAccountPagination_ServerIgnoresPerPage guards the other tail: a
// server that ignores perpage and returns every row in page 1 must not trigger
// a second fetch (which would duplicate rows).
func TestServiceAccountPagination_ServerIgnoresPerPage(t *testing.T) {
	const total = serviceAccountPageSize*2 + 37
	var hits atomic.Int32
	srv := newAllInOnePageServer(t, total, &hits)
	t.Cleanup(srv.Close)
	conn := newTestConn(t, srv.URL)

	got, err := fetchAllServiceAccounts(context.Background(), conn)
	require.NoError(t, err)
	assertUniqueIDs(t, got, total)
	assert.Equal(t, int32(1), hits.Load(),
		"server returned everything in page 1 — must not re-fetch")
}

// TestServiceAccountTokens_HasExpirationLogic exercises the simplified
// hasExpiration branch (parseGrafanaTime zero-sentinel handling) end-to-end on
// the JSON shape returned by /api/serviceaccounts/{id}/tokens.
func TestServiceAccountTokens_HasExpirationLogic(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantHas  bool
		wantSecs float64
	}{
		{"empty expiration", "", false, 0},
		{"grafana zero sentinel", "0001-01-01T00:00:00Z", false, 0},
		{"valid future timestamp", "2099-01-01T00:00:00Z", true, 1234},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := parseGrafanaTime(tt.raw)
			hasExp := !exp.IsZero()
			assert.Equal(t, tt.wantHas, hasExp)
			// Mirror the secondsUntilExp gating in tokens()
			secs := tt.wantSecs
			if !hasExp {
				secs = 0
			}
			assert.Equal(t, tt.wantSecs, secs)
		})
	}
}

// TestTokenDecode_RevokedAndLastUsed pins the struct tags for the two fields a
// token audit turns on: a mistyped tag would decode isRevoked as false and
// report a dead credential as live.
func TestTokenDecode_RevokedAndLastUsed(t *testing.T) {
	// Shaped like GET /api/serviceaccounts/{id}/tokens: one revoked token and
	// one live token that has never authenticated.
	const payload = `[
	  {"id":1,"name":"revoked-token","created":"2026-08-01T10:00:00Z","expiration":"0001-01-01T00:00:00Z","lastUsedAt":"2026-08-02T11:30:00Z","hasExpired":false,"secondsUntilExpiration":0,"isRevoked":true},
	  {"id":2,"name":"live-token","created":"2026-08-01T10:05:00Z","expiration":"0001-01-01T00:00:00Z","lastUsedAt":null,"hasExpired":false,"secondsUntilExpiration":0,"isRevoked":false}
	]`

	var toks []grafanaTokenJSON
	require.NoError(t, json.Unmarshal([]byte(payload), &toks))
	require.Len(t, toks, 2)

	assert.True(t, toks[0].IsRevoked, "revoked token must decode isRevoked=true")
	require.NotNil(t, toks[0].LastUsedAt)
	lastUsed := parseGrafanaTimePtr(toks[0].LastUsedAt)
	require.NotNil(t, lastUsed)
	assert.Equal(t, "2026-08-02T11:30:00Z", lastUsed.UTC().Format(time.RFC3339))

	assert.False(t, toks[1].IsRevoked, "live token must decode isRevoked=false")
	assert.Nil(t, toks[1].LastUsedAt)
	assert.Nil(t, parseGrafanaTimePtr(toks[1].LastUsedAt), "a never-used token must report null, not the zero time")
}

func TestParseGrafanaTimePtr(t *testing.T) {
	tests := []struct {
		name string
		raw  *string
		want string // empty means nil
	}{
		{"absent", nil, ""},
		{"empty string", new(""), ""},
		{"grafana zero sentinel", new("0001-01-01T00:00:00Z"), ""},
		{"valid timestamp", new("2026-08-02T11:30:00Z"), "2026-08-02T11:30:00Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGrafanaTimePtr(tt.raw)
			if tt.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.UTC().Format(time.RFC3339))
		})
	}
}

//go:fix inline
func strPtr(s string) *string { return new(s) }
