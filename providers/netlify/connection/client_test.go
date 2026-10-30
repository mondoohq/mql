// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

type pagedItem struct {
	ID string `json:"id"`
}

func testConn(srv *httptest.Server) *NetlifyConnection {
	return &NetlifyConnection{
		token:   "test-token",
		baseURL: srv.URL,
		client:  srv.Client(),
	}
}

// writeItems answers with a page of n items, each carrying a unique id derived
// from the page number so the test can tell pages apart.
func writeItems(w http.ResponseWriter, page, n int) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "[")
	for i := range n {
		if i > 0 {
			io.WriteString(w, ",")
		}
		fmt.Fprintf(w, `{"id":"p%d-%d"}`, page, i)
	}
	io.WriteString(w, "]")
}

func TestGetPagedWalksUntilShortPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/incorrect auth header: %q", got)
		}
		if got := r.URL.Query().Get("per_page"); got != strconv.Itoa(pageSize) {
			t.Errorf("expected per_page=%d, got %q", pageSize, got)
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		switch page {
		case 1:
			writeItems(w, 1, pageSize)
		case 2:
			writeItems(w, 2, 3)
		default:
			t.Errorf("unexpected page request: %d", page)
		}
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil)
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 page requests, got %d", calls)
	}
	if len(got) != pageSize+3 {
		t.Fatalf("expected %d records, got %d", pageSize+3, len(got))
	}
	if got[0].ID != "p1-0" || got[pageSize].ID != "p2-0" {
		t.Fatalf("pages collected out of order: %q then %q", got[0].ID, got[pageSize].ID)
	}
}

// An endpoint that ignores the page parameter replays the first page forever.
// Without the duplicate guard the walk would collect the same records up to the
// page cap, silently multiplying every result.
func TestGetPagedStopsWhenEndpointIgnoresPaging(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeItems(w, 1, pageSize)
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil)
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the walk to stop after the repeated page, got %d requests", calls)
	}
	if len(got) != pageSize {
		t.Fatalf("expected the repeated page to be dropped, got %d records", len(got))
	}
}

func TestGetPagedSinglePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeItems(w, 1, 2)
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil)
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
}

func TestErrorsCarryStatusAndMessage(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantMessage string
		forbidden   bool
		notFound    bool
	}{
		{
			name:        "forbidden with message envelope",
			status:      http.StatusForbidden,
			body:        `{"message":"You must be an owner"}`,
			wantMessage: "You must be an owner",
			forbidden:   true,
		},
		{
			name:        "unauthorized counts as forbidden",
			status:      http.StatusUnauthorized,
			body:        `{"message":"Access denied"}`,
			wantMessage: "Access denied",
			forbidden:   true,
		},
		{
			name:        "error envelope key",
			status:      http.StatusNotFound,
			body:        `{"error":"Not Found"}`,
			wantMessage: "Not Found",
			notFound:    true,
		},
		{
			name:   "non-json body still reports the status",
			status: http.StatusInternalServerError,
			body:   `<html>oops</html>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			err := testConn(srv).Get(context.Background(), "/thing", nil, nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			apiErr, ok := err.(*APIError)
			if !ok {
				t.Fatalf("expected *APIError, got %T", err)
			}
			if apiErr.StatusCode != tc.status {
				t.Errorf("expected status %d, got %d", tc.status, apiErr.StatusCode)
			}
			if apiErr.Message != tc.wantMessage {
				t.Errorf("expected message %q, got %q", tc.wantMessage, apiErr.Message)
			}
			if IsForbidden(err) != tc.forbidden {
				t.Errorf("IsForbidden: expected %v", tc.forbidden)
			}
			if IsNotFound(err) != tc.notFound {
				t.Errorf("IsNotFound: expected %v", tc.notFound)
			}
		})
	}
}

// A transport failure is not an APIError, so the degrade-to-null helpers must
// not treat it as an access-denied response.
func TestClassifiersRejectNonAPIErrors(t *testing.T) {
	err := fmt.Errorf("dial tcp: connection refused")
	if IsForbidden(err) {
		t.Error("IsForbidden must not match a transport error")
	}
	if IsNotFound(err) {
		t.Error("IsNotFound must not match a transport error")
	}
}

// The account a discovered asset is scoped to arrives under a different key
// than the --account flag. Reading only the flag leaves every discovered asset
// unscoped, so it reports every account the token can reach rather than its
// own.
func TestAccountFilterPrefersTheDiscoveredAccount(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]string
		want    string
	}{
		{"discovered asset", map[string]string{"accountId": "acct_1"}, "acct_1"},
		{"flag only", map[string]string{"account": "acme"}, "acme"},
		{"discovered asset wins over the flag", map[string]string{"accountId": "acct_1", "account": "acme"}, "acct_1"},
		{"unscoped", map[string]string{}, ""},
		{"no options at all", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &NetlifyConnection{Conf: &inventory.Config{Options: tc.options}}
			if got := c.AccountFilter(); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestSiteFilterReadsTheDiscoveredSite(t *testing.T) {
	c := &NetlifyConnection{Conf: &inventory.Config{Options: map[string]string{"siteId": "site_1"}}}
	if got := c.SiteFilter(); got != "site_1" {
		t.Fatalf("expected site_1, got %q", got)
	}
	if got := (&NetlifyConnection{}).SiteFilter(); got != "" {
		t.Fatalf("expected an unscoped connection to report no site, got %q", got)
	}
}

func TestGetPagedLimitStopsAtTheRecordCap(t *testing.T) {
	// An append-only endpoint keeps answering with full pages, so the walk has
	// to stop on the cap rather than on a short page. It must also report
	// exactly the cap, not the whole last page it read past it.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		writeItems(w, page, pageSize)
	}))
	defer srv.Close()

	got, err := GetPagedLimit[pagedItem](context.Background(), testConn(srv), "/deploys", nil, 250)
	if err != nil {
		t.Fatalf("GetPagedLimit: %v", err)
	}
	if len(got) != 250 {
		t.Fatalf("expected 250 records, got %d", len(got))
	}
	if calls != 3 {
		t.Fatalf("expected 3 page requests, got %d", calls)
	}
	// Newest first, so the cap keeps the most recent records.
	if got[0].ID != "p1-0" {
		t.Fatalf("dropped the newest records: %q", got[0].ID)
	}
}

func TestGetPagedLimitStopsOnAStuckCursor(t *testing.T) {
	// An endpoint that ignores the page parameter answers every request with
	// the first page. Without the guard the cap alone would still be reached,
	// by counting the same records over and over.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeItems(w, 1, pageSize)
	}))
	defer srv.Close()

	got, err := GetPagedLimit[pagedItem](context.Background(), testConn(srv), "/deploys", nil, 1000)
	if err != nil {
		t.Fatalf("GetPagedLimit: %v", err)
	}
	if len(got) != pageSize {
		t.Fatalf("expected %d records, got %d", pageSize, len(got))
	}
	if calls != 2 {
		t.Fatalf("expected 2 page requests before the repeat was detected, got %d", calls)
	}
}

func TestGetPagedLimitShortPageWins(t *testing.T) {
	// A cap larger than the data must not change the plain behavior: the walk
	// still ends on the short page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeItems(w, 1, 2)
	}))
	defer srv.Close()

	got, err := GetPagedLimit[pagedItem](context.Background(), testConn(srv), "/deploys", nil, 500)
	if err != nil {
		t.Fatalf("GetPagedLimit: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
}
