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
)

type pagedItem struct {
	ID string `json:"id"`
}

func testConn(srv *httptest.Server) *NeonConnection {
	return &NeonConnection{
		token:   "test-token",
		baseURL: srv.URL,
		client:  srv.Client(),
	}
}

// writePage answers with an envelope holding n items under key, plus the cursor
// the next request should send. An empty cursor ends the walk.
func writePage(w http.ResponseWriter, key string, page, n int, cursor string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{%q:[`, key)
	for i := range n {
		if i > 0 {
			io.WriteString(w, ",")
		}
		fmt.Fprintf(w, `{"id":"p%d-%d"}`, page, i)
	}
	io.WriteString(w, "]")
	if cursor != "" {
		fmt.Fprintf(w, `,"pagination":{"cursor":%q}`, cursor)
	}
	io.WriteString(w, "}")
}

func TestGetPagedCursorFollowsCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/incorrect auth header: %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != strconv.Itoa(pageSize) {
			t.Errorf("expected limit=%d, got %q", pageSize, got)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			writePage(w, "projects", 1, pageSize, "cursor-2")
		case "cursor-2":
			writePage(w, "projects", 2, 3, "")
		default:
			t.Errorf("unexpected cursor: %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	got, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedCursor: %v", err)
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

// A short page ends the walk even when the endpoint keeps handing back a
// cursor, which is what Neon does on the final page of a list.
func TestGetPagedCursorStopsOnShortPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writePage(w, "projects", 1, 2, "cursor-next")
	}))
	defer srv.Close()

	got, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedCursor: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected the walk to stop after the short page, got %d requests", calls)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
}

// An endpoint that echoes the cursor it was sent would otherwise replay the
// same page until the page cap, multiplying every record.
func TestGetPagedCursorStopsOnStationaryCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writePage(w, "projects", 1, pageSize, "stuck")
	}))
	defer srv.Close()

	got, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedCursor: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the walk to stop once the cursor stopped moving, got %d requests", calls)
	}
	if len(got) != 2*pageSize {
		t.Fatalf("expected the two fetched pages, got %d records", len(got))
	}
}

// A key the response does not carry is an empty result, not a decode failure.
func TestGetPagedCursorMissingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"pagination":{"cursor":""}}`)
	}))
	defer srv.Close()

	got, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedCursor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no records, got %d", len(got))
	}
}

func TestGetListReadsEnvelopeKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"branches":[{"id":"br-1"},{"id":"br-2"}]}`)
	}))
	defer srv.Close()

	got, err := GetList[pagedItem](context.Background(), testConn(srv), "/branches", nil, "branches")
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if len(got) != 2 || got[1].ID != "br-2" {
		t.Fatalf("unexpected records: %+v", got)
	}
}

// The API key endpoints answer with a bare array rather than an envelope.
func TestGetListReadsBareArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"id":"key-1"}]`)
	}))
	defer srv.Close()

	got, err := GetList[pagedItem](context.Background(), testConn(srv), "/api_keys", nil, "")
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if len(got) != 1 || got[0].ID != "key-1" {
		t.Fatalf("unexpected records: %+v", got)
	}
}

// A null value under the key is an empty list, which is how Neon reports a
// project with no key set registered.
func TestGetListNullKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jwks":null}`)
	}))
	defer srv.Close()

	got, err := GetList[pagedItem](context.Background(), testConn(srv), "/jwks", nil, "jwks")
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no records, got %d", len(got))
	}
}

func TestErrorsCarryStatusCodeAndMessage(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantCode    string
		wantMessage string
		forbidden   bool
		notFound    bool
	}{
		{
			name:        "forbidden carries the neon error code",
			status:      http.StatusForbidden,
			body:        `{"code":"FORBIDDEN","message":"not a member of this organization"}`,
			wantCode:    "FORBIDDEN",
			wantMessage: "not a member of this organization",
			forbidden:   true,
		},
		{
			name:        "unauthorized counts as forbidden",
			status:      http.StatusUnauthorized,
			body:        `{"code":"UNAUTHORIZED","message":"invalid api key"}`,
			wantCode:    "UNAUTHORIZED",
			wantMessage: "invalid api key",
			forbidden:   true,
		},
		{
			name:        "not found",
			status:      http.StatusNotFound,
			body:        `{"code":"NOT_FOUND","message":"project not found"}`,
			wantCode:    "NOT_FOUND",
			wantMessage: "project not found",
			notFound:    true,
		},
		{
			name:   "non-json body still reports the status",
			status: http.StatusBadGateway,
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
			if apiErr.Code != tc.wantCode {
				t.Errorf("expected code %q, got %q", tc.wantCode, apiErr.Code)
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

// writeNextPage answers with the newer pagination shape, which carries the next
// cursor as `next` rather than as `cursor`. A project's branches, an
// organization's members, and a branch's functions all use this shape.
func writeNextPage(w http.ResponseWriter, key string, page, n int, next string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{%q:[`, key)
	for i := range n {
		if i > 0 {
			io.WriteString(w, ",")
		}
		fmt.Fprintf(w, `{"id":"p%d-%d"}`, page, i)
	}
	io.WriteString(w, "]")
	if next != "" {
		fmt.Fprintf(w, `,"pagination":{"next":%q,"sort_by":"id","sort_order":"asc"}`, next)
	}
	io.WriteString(w, "}")
}

func TestGetPagedCursorFollowsNextCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// The next page is requested with the `cursor` query parameter even
		// though the response named it `next`.
		switch r.URL.Query().Get("cursor") {
		case "":
			writeNextPage(w, "branches", 1, pageSize, "next-2")
		case "next-2":
			writeNextPage(w, "branches", 2, 4, "")
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	items, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/branches", nil, "branches")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// Reading only `cursor` would stop after the first page and report the
	// branch list as complete at pageSize entries.
	if len(items) != pageSize+4 {
		t.Errorf("expected %d items, got %d", pageSize+4, len(items))
	}
	if calls != 2 {
		t.Errorf("expected 2 requests, got %d", calls)
	}
}

func TestGetPagedCursorStopsOnStationaryNextCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// An endpoint that ignores the cursor replays the same page forever.
		writeNextPage(w, "members", 1, pageSize, "stuck")
	}))
	defer srv.Close()

	items, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/members", nil, "members")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected the walk to stop after the repeated cursor, got %d requests", calls)
	}
	if len(items) != 2*pageSize {
		t.Errorf("expected %d items, got %d", 2*pageSize, len(items))
	}
}

func TestGetPagedCursorPrefersNextOverCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"items":[`)
			for i := range pageSize {
				if i > 0 {
					io.WriteString(w, ",")
				}
				fmt.Fprintf(w, `{"id":"a-%d"}`, i)
			}
			io.WriteString(w, `],"pagination":{"next":"use-me","cursor":""}}`)
		case "use-me":
			writeNextPage(w, "items", 2, 1, "")
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	items, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/items", nil, "items")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(items) != pageSize+1 {
		t.Errorf("expected %d items, got %d", pageSize+1, len(items))
	}
}

func TestGetPagedCursorStopsWhenNeitherCursorIsPresent(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// A full page with no pagination object at all is the last page.
		writeNextPage(w, "items", 1, pageSize, "")
	}))
	defer srv.Close()

	items, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/items", nil, "items")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 request, got %d", calls)
	}
	if len(items) != pageSize {
		t.Errorf("expected %d items, got %d", pageSize, len(items))
	}
}
