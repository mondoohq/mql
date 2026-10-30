// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/nextdns/connection"
)

// testConn points a NextDNS connection at a test server. The profile option is
// left unset so the account-level listing (the paginated path) is exercised.
func testConn(t *testing.T, baseURL string, opts map[string]string) *connection.NextdnsConnection {
	t.Helper()
	t.Setenv("NEXTDNS_API_KEY", "test-key")

	options := map[string]string{"base-url": baseURL}
	maps.Copy(options, opts)

	conn, err := connection.NewNextdnsConnection(1, &inventory.Asset{}, &inventory.Config{Options: options})
	if err != nil {
		t.Fatalf("connection: %v", err)
	}
	return conn
}

// A listing longer than one page must yield every profile. Stopping at the
// first page reports a short enumeration as a successful scan, so every
// finding on an unlisted profile silently does not exist.
func TestFetchProfilesFollowsTheCursorToExhaustion(t *testing.T) {
	var requests []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{
				"data": [
					{"id":"aaa111","name":"home","fingerprint":"fp-aaa111"},
					{"id":"bbb222","name":"office","fingerprint":"fp-bbb222"}
				],
				"meta": {"pagination": {"cursor": "page-2"}}
			}`))
		case "page-2":
			_, _ = w.Write([]byte(`{
				"data": [
					{"id":"ccc333","name":"lab","fingerprint":"fp-ccc333"}
				],
				"meta": {"pagination": {"cursor": ""}}
			}`))
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	profiles, err := fetchProfiles(testConn(t, srv.URL, nil))
	if err != nil {
		t.Fatalf("fetchProfiles: %v", err)
	}

	want := []string{"aaa111", "bbb222", "ccc333"}
	if len(profiles) != len(want) {
		t.Fatalf("expected %d profiles, got %d: %+v", len(want), len(profiles), profiles)
	}
	for i, id := range want {
		if profiles[i].ID != id {
			t.Errorf("profile %d: expected id %q, got %q", i, id, profiles[i].ID)
		}
	}
	if profiles[2].Name != "lab" || profiles[2].Fingerprint != "fp-ccc333" {
		t.Errorf("second page did not decode: %+v", profiles[2])
	}

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d: %v", len(requests), requests)
	}
	if requests[0] != "/profiles" {
		t.Errorf("first request should carry no cursor, got %q", requests[0])
	}
	if requests[1] != "/profiles?cursor=page-2" {
		t.Errorf("second request should carry the cursor, got %q", requests[1])
	}
}

// A single page must still work, and must not cost a second request.
func TestFetchProfilesSinglePage(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":[{"id":"aaa111","name":"home","fingerprint":"fp-aaa111"}]}`))
	}))
	defer srv.Close()

	profiles, err := fetchProfiles(testConn(t, srv.URL, nil))
	if err != nil {
		t.Fatalf("fetchProfiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].ID != "aaa111" {
		t.Fatalf("unexpected profiles: %+v", profiles)
	}
	if calls != 1 {
		t.Errorf("an absent cursor must end the walk, got %d requests", calls)
	}
}

// A server that hands back the same cursor forever must terminate the walk
// rather than spin the scan, and must not report the truncated list as a
// complete one.
func TestFetchProfilesStuckCursorTerminates(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 50 {
			t.Fatalf("pagination walk did not terminate: %d requests", calls)
		}
		_, _ = w.Write([]byte(`{
			"data": [{"id":"aaa111","name":"home","fingerprint":"fp-aaa111"}],
			"meta": {"pagination": {"cursor": "stuck"}}
		}`))
	}))
	defer srv.Close()

	profiles, err := fetchProfiles(testConn(t, srv.URL, nil))
	if err == nil {
		t.Fatalf("expected an error for a repeated cursor, got %d profiles", len(profiles))
	}
	if profiles != nil {
		t.Errorf("an incomplete listing must not be returned, got %+v", profiles)
	}
	if calls != 2 {
		t.Errorf("expected the repeat to be caught on the second request, got %d", calls)
	}
}

// A profile-scoped connection reads the single profile directly and never
// touches the paginated listing.
func TestFetchProfilesScopedConnectionSkipsTheListing(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"id":"aaa111","name":"home","fingerprint":"fp-aaa111"}}`))
	}))
	defer srv.Close()

	conn := testConn(t, srv.URL, map[string]string{connection.OptionProfile: "aaa111"})
	profiles, err := fetchProfiles(conn)
	if err != nil {
		t.Fatalf("fetchProfiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "home" {
		t.Fatalf("unexpected profiles: %+v", profiles)
	}
	if len(paths) != 1 || paths[0] != "/profiles/aaa111" {
		t.Errorf("expected a single direct profile read, got %v", paths)
	}
}

// An error on a later page must fail the fetch rather than silently return the
// pages already gathered.
func TestFetchProfilesPropagatesLaterPageErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = w.Write([]byte(`{
				"data": [{"id":"aaa111","name":"home","fingerprint":"fp-aaa111"}],
				"meta": {"pagination": {"cursor": "page-2"}}
			}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[{"code":"internal"}]}`))
	}))
	defer srv.Close()

	profiles, err := fetchProfiles(testConn(t, srv.URL, nil))
	if err == nil {
		t.Fatalf("expected an error, got %d profiles", len(profiles))
	}
	if profiles != nil {
		t.Errorf("a failed walk must not return partial results, got %+v", profiles)
	}
}
