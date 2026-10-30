// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type pagedItem struct {
	ID string `json:"id"`
}

func testConn(srv *httptest.Server) *VercelConnection {
	return &VercelConnection{
		token:   "test-token",
		baseURL: srv.URL,
		client:  srv.Client(),
	}
}

func TestGetPagedFollowsCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/incorrect auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("until") {
		case "":
			// first page hands back a cursor
			io.WriteString(w, `{"items":[{"id":"a"},{"id":"b"}],"pagination":{"next":100}}`)
		case "100":
			// last page terminates the cursor
			io.WriteString(w, `{"items":[{"id":"c"}],"pagination":{"next":null}}`)
		default:
			t.Errorf("unexpected until cursor: %q", r.URL.Query().Get("until"))
		}
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil, "items")
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 page requests, got %d", calls)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("index %d: expected %q, got %q", i, want[i], got[i].ID)
		}
	}
}

func TestGetPagedCursorFollowsStringCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("next") {
		case "":
			io.WriteString(w, `{"members":[{"id":"a"},{"id":"b"}],"pagination":{"count":2,"next":"cursor-2"}}`)
		case "cursor-2":
			io.WriteString(w, `{"members":[{"id":"c"}],"pagination":{"count":1,"next":null}}`)
		default:
			t.Errorf("unexpected next cursor: %q", r.URL.Query().Get("next"))
		}
	}))
	defer srv.Close()

	got, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/members", nil, "members")
	if err != nil {
		t.Fatalf("GetPagedCursor: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 page requests, got %d", calls)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("index %d: expected %q, got %q", i, want[i], got[i].ID)
		}
	}
}

func TestGetPagedSinglePageNoPagination(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `{"items":[{"id":"only"}]}`)
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil, "items")
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 request without a pagination envelope, got %d", calls)
	}
	if len(got) != 1 || got[0].ID != "only" {
		t.Fatalf("expected [only], got %v", got)
	}
}

func TestGetPagedDropsReplayedPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// An endpoint that reports a cursor but ignores the until parameter
		// answers every request with the same first page. Without the guard
		// this loops forever; without dropping the replay it silently doubles
		// every record.
		io.WriteString(w, `{"items":[{"id":"a"}],"pagination":{"next":100}}`)
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil, "items")
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the cursor to stop advancing after 2 requests, got %d", calls)
	}
	if len(got) != 1 {
		t.Fatalf("replayed page must be dropped, expected 1 item, got %d: %v", len(got), got)
	}
}

func TestGetPagedFromFollowsTokenCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Query().Get("from") {
		case "":
			io.WriteString(w, `{"projects":[{"id":"a"}],"pagination":{"count":1,"next":"tok-2"}}`)
		case "tok-2":
			io.WriteString(w, `{"projects":[{"id":"b"}],"pagination":{"count":1,"next":null}}`)
		default:
			t.Errorf("unexpected from cursor: %q", r.URL.Query().Get("from"))
		}
	}))
	defer srv.Close()

	got, err := GetPagedFrom[pagedItem](context.Background(), testConn(srv), "/v10/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedFrom: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 page requests, got %d", calls)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("expected items a,b; got %v", got)
	}
}

func TestGetPagedFromAcceptsNumericCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The same endpoint may page with a timestamp instead of a token.
		switch r.URL.Query().Get("from") {
		case "":
			io.WriteString(w, `{"projects":[{"id":"a"}],"pagination":{"next":1700000000000}}`)
		case "1700000000000":
			io.WriteString(w, `{"projects":[{"id":"b"}],"pagination":{"next":null}}`)
		default:
			t.Errorf("unexpected from cursor: %q", r.URL.Query().Get("from"))
		}
	}))
	defer srv.Close()

	got, err := GetPagedFrom[pagedItem](context.Background(), testConn(srv), "/v10/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedFrom: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d", len(got))
	}
}

func TestGetPagedFromDropsReplayedPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `{"projects":[{"id":"a"}],"pagination":{"next":"same-token"}}`)
	}))
	defer srv.Close()

	got, err := GetPagedFrom[pagedItem](context.Background(), testConn(srv), "/v10/projects", nil, "projects")
	if err != nil {
		t.Fatalf("GetPagedFrom: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the cursor to stop advancing after 2 requests, got %d", calls)
	}
	if len(got) != 1 {
		t.Fatalf("replayed page must be dropped, expected 1 item, got %d: %v", len(got), got)
	}
}

func TestCursorValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"opaque token", `"tok-abc"`, "tok-abc"},
		{"numeric timestamp", `1700000000000`, "1700000000000"},
		{"unusable object", `{"a":1}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cursorValue([]byte(tc.raw)); got != tc.want {
				t.Errorf("cursorValue(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestGetPagedMissingKeyReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"other":[{"id":"x"}]}`)
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil, "items")
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result when key absent, got %v", got)
	}
}

func TestGetPagedSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":{"code":"forbidden","message":"nope"}}`)
	}))
	defer srv.Close()

	_, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/things", nil, "items")
	if err == nil {
		t.Fatal("expected an error on 403")
	}
	if !IsForbidden(err) {
		t.Fatalf("expected IsForbidden to be true, got %v", err)
	}
	var apiErr *APIError
	if !asAPIError(err, &apiErr) {
		t.Fatalf("expected an *APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Code != "forbidden" || apiErr.Message != "nope" {
		t.Fatalf("APIError not populated from envelope: %+v", apiErr)
	}
}

func TestErrorClassificationThroughWrap(t *testing.T) {
	// IsForbidden / IsNotFound must see through a wrapped APIError, otherwise
	// enterprise-gated 403s propagate as hard errors instead of degrading.
	forbidden := fmt.Errorf("call failed: %w", &APIError{StatusCode: http.StatusForbidden})
	if !IsForbidden(forbidden) {
		t.Error("IsForbidden should unwrap a wrapped 403")
	}
	if IsNotFound(forbidden) {
		t.Error("IsNotFound should be false for a 403")
	}

	notFound := fmt.Errorf("call failed: %w", &APIError{StatusCode: http.StatusNotFound})
	if !IsNotFound(notFound) {
		t.Error("IsNotFound should unwrap a wrapped 404")
	}
	if IsForbidden(notFound) {
		t.Error("IsForbidden should be false for a 404")
	}

	if IsForbidden(fmt.Errorf("plain error")) {
		t.Error("IsForbidden should be false for a non-APIError")
	}
}

// An endpoint that reports a string cursor but ignores the next parameter
// replays the first page forever. Without the guard this loops until the
// process is killed; with it the records are collected once.
func TestGetPagedCursorDropsReplayedPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 8 {
			t.Fatal("GetPagedCursor did not terminate on a stuck cursor")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"items":[{"id":"a"}],"pagination":{"next":"stuck"}}`)
	}))
	defer srv.Close()

	got, err := GetPagedCursor[pagedItem](context.Background(), testConn(srv), "/things", nil, "items")
	if err != nil {
		t.Fatalf("GetPagedCursor: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("got %v, want the replayed records collected once", got)
	}
	if calls != 2 {
		t.Errorf("made %d requests, want 2 (first page then the echoed cursor)", calls)
	}
}

// The team invitations arrive under a key that is a sibling of the paginated
// member list, so a multi-page member walk can hand the same invitations back
// on every page. The walk must collect them all; the caller drops repeats.
func TestGetPagedCollectsSiblingKeyAcrossPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("until") {
		case "":
			io.WriteString(w, `{"members":[{"id":"m1"}],"emailInviteCodes":[{"id":"inv_1"}],"pagination":{"next":100}}`)
		case "100":
			io.WriteString(w, `{"members":[{"id":"m2"}],"emailInviteCodes":[{"id":"inv_1"},{"id":"inv_2"}],"pagination":{"next":null}}`)
		default:
			t.Errorf("unexpected until cursor: %q", r.URL.Query().Get("until"))
		}
	}))
	defer srv.Close()

	got, err := GetPaged[pagedItem](context.Background(), testConn(srv), "/v3/teams/team_1/members", nil, "emailInviteCodes")
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	want := []string{"inv_1", "inv_1", "inv_2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// A transport failure is not an access decision. Classifying it as forbidden
// or not-found would turn a network blip into an empty security field.
func TestErrorClassifiersRejectTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // refuse the connection

	err := testConn(srv).Get(context.Background(), "/things", nil, nil)
	if err == nil {
		t.Fatal("a refused connection must surface as an error")
	}
	if IsForbidden(err) {
		t.Error("a transport error must not classify as forbidden")
	}
	if IsNotFound(err) {
		t.Error("a transport error must not classify as not found")
	}
}
