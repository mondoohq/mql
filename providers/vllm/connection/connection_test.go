// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestDefaultEndpointSpecsCoverSourceBackedRoutes(t *testing.T) {
	specs := DefaultEndpointSpecs()
	required := []EndpointSpec{
		{Method: http.MethodPost, Path: "/invocations"},
		{Method: http.MethodPost, Path: "/tokenize"},
		{Method: http.MethodPost, Path: "/detokenize"},
		{Method: http.MethodGet, Path: "/version"},
		{Method: http.MethodGet, Path: "/load"},
		{Method: http.MethodGet, Path: "/tokenizer_info"},
		{Method: http.MethodPost, Path: "/collective_rpc"},
	}

	for _, want := range required {
		if !slices.ContainsFunc(specs, func(got EndpointSpec) bool {
			return got.Method == want.Method && got.Path == want.Path
		}) {
			t.Fatalf("missing default probe %s %s", want.Method, want.Path)
		}
	}
}

var specSink []EndpointSpec

// The spec table is looked up once per endpoint resource, so rebuilding it per
// call is 39 structs of garbage each time. Guard the sharing rather than the
// wording of the implementation.
func TestDefaultEndpointSpecsDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		specSink = DefaultEndpointSpecs()
	})
	if allocs != 0 {
		t.Fatalf("DefaultEndpointSpecs allocates %.0f times per call, want 0 (the table must be shared, not rebuilt)", allocs)
	}
}

// ProbeEndpoint uppercases the method on its own copy. If it ever took a
// pointer, or a caller sorted the returned slice, every later lookup would see
// the mutation because the table is now shared.
func TestProbeEndpointDoesNotMutateSharedTable(t *testing.T) {
	specs := DefaultEndpointSpecs()
	idx := slices.IndexFunc(specs, func(s EndpointSpec) bool { return s.Path == "/v1/models" })
	if idx < 0 {
		t.Fatal("expected /v1/models in the default specs")
	}
	before := specs[idx]

	lower := before
	lower.Method = "get"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	conn := &VllmConnection{client: srv.Client(), baseURL: srv.URL}
	conn.ProbeEndpoint(context.Background(), lower)

	if got := DefaultEndpointSpecs()[idx]; got != before {
		t.Fatalf("shared spec table was mutated: %+v, want %+v", got, before)
	}
}

func TestObservationClassification(t *testing.T) {
	tests := []struct {
		name              string
		status            *int
		present           bool
		accessible        bool
		accessibleKnown   bool
		requiresAuth      bool
		requiresAuthKnown bool
	}{
		{name: "validation means anonymous reached route", status: intPtr(http.StatusUnprocessableEntity), present: true, accessible: true, accessibleKnown: true, requiresAuth: false, requiresAuthKnown: true},
		{name: "unauthorized means auth required", status: intPtr(http.StatusUnauthorized), present: true, accessible: false, accessibleKnown: true, requiresAuth: true, requiresAuthKnown: true},
		{name: "not found means absent", status: intPtr(http.StatusNotFound), present: false, accessible: false, accessibleKnown: true, requiresAuth: false, requiresAuthKnown: false},
		{name: "not implemented means absent", status: intPtr(http.StatusNotImplemented), present: false, accessible: false, accessibleKnown: true, requiresAuth: false, requiresAuthKnown: false},
		{name: "server error is ambiguous", status: intPtr(http.StatusInternalServerError), present: true, accessible: false, accessibleKnown: false, requiresAuth: false, requiresAuthKnown: false},
		{name: "network error is unknown", status: nil, present: false, accessible: false, accessibleKnown: false, requiresAuth: false, requiresAuthKnown: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := EndpointObservation{AnonymousStatusCode: tt.status}
			if got := ObservationPresent(obs); got != tt.present {
				t.Fatalf("present got %v want %v", got, tt.present)
			}
			accessible, known := ObservationAnonymousAccessible(obs)
			if accessible != tt.accessible || known != tt.accessibleKnown {
				t.Fatalf("anonymousAccessible got (%v,%v) want (%v,%v)", accessible, known, tt.accessible, tt.accessibleKnown)
			}
			requiresAuth, known := ObservationRequiresAuth(obs)
			if requiresAuth != tt.requiresAuth || known != tt.requiresAuthKnown {
				t.Fatalf("requiresAuth got (%v,%v) want (%v,%v)", requiresAuth, known, tt.requiresAuth, tt.requiresAuthKnown)
			}
		})
	}
}

func TestProbeEndpointUsesMethodBodyAndAuth(t *testing.T) {
	var sawAuth bool
	var sawBody bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method got %s want POST", r.Method)
		}
		if r.Header.Get("Authorization") == "Bearer test-token" {
			sawAuth = true
		}
		if r.ContentLength != 0 {
			sawBody = true
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			OptionBaseURL: server.URL,
			OptionAPIKey:  "test-token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	obs := conn.ProbeEndpoint(context.Background(), EndpointSpec{
		Method: http.MethodPost,
		Path:   "/tokenize",
		Body:   NewPostBody(),
	})
	if obs.AnonymousStatusCode == nil || *obs.AnonymousStatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("anonymous status = %v", obs.AnonymousStatusCode)
	}
	if obs.AuthenticatedStatusCode == nil || *obs.AuthenticatedStatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("authenticated status = %v", obs.AuthenticatedStatusCode)
	}
	if !sawAuth {
		t.Fatal("authenticated probe did not send bearer token")
	}
	if !sawBody {
		t.Fatal("POST probe did not send a request body")
	}
}

func TestCORSUsesRealPreflightHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			t.Fatalf("method got %s want OPTIONS", r.Method)
		}
		if r.Header.Get("Origin") == "" {
			t.Fatal("missing Origin header")
		}
		if r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
			t.Fatalf("Access-Control-Request-Method = %q, want POST", r.Header.Get("Access-Control-Request-Method"))
		}
		if r.Header.Get("Access-Control-Request-Headers") == "" {
			t.Fatal("missing Access-Control-Request-Headers")
		}

		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionBaseURL: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	obs, err := conn.CORS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if obs.Configured == nil || !*obs.Configured {
		t.Fatalf("configured = %v, want true", obs.Configured)
	}
	if obs.AllowsAnyOrigin == nil || *obs.AllowsAnyOrigin {
		t.Fatalf("allows any origin = %v, want false", obs.AllowsAnyOrigin)
	}
}

func TestCORSWildcardAllowsAnyOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionBaseURL: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	obs, err := conn.CORS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if obs.AllowsAnyOrigin == nil || !*obs.AllowsAnyOrigin {
		t.Fatalf("allows any origin = %v, want true", obs.AllowsAnyOrigin)
	}
}

func TestProbeEndpointDoesNotFollowRedirects(t *testing.T) {
	loginHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			loginHit = true
			if r.Header.Get("Authorization") != "" {
				t.Fatal("authorization header was forwarded to redirect target")
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			OptionBaseURL: server.URL,
			OptionAPIKey:  "test-token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	obs := conn.ProbeEndpoint(context.Background(), EndpointSpec{
		Method: http.MethodGet,
		Path:   "/v1/models",
	})
	if obs.AnonymousStatusCode == nil || *obs.AnonymousStatusCode != http.StatusFound {
		t.Fatalf("anonymous status = %v, want 302", obs.AnonymousStatusCode)
	}
	if obs.AuthenticatedStatusCode == nil || *obs.AuthenticatedStatusCode != http.StatusFound {
		t.Fatalf("authenticated status = %v, want 302", obs.AuthenticatedStatusCode)
	}
	if loginHit {
		t.Fatal("probe followed redirect target")
	}
}

func TestVersionParsesJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.17.0"}`))
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionBaseURL: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	version, err := conn.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "0.17.0" {
		t.Fatalf("version = %q, want 0.17.0", version)
	}
}

func TestVersionRejectsNonSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Not authenticated"}`))
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionBaseURL: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	version, err := conn.Version(context.Background())
	if err == nil {
		t.Fatal("expected /version error")
	}
	if version != "" {
		t.Fatalf("version = %q, want empty", version)
	}
}

func TestVersionIgnoresNonJSONSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not a version"))
	}))
	defer server.Close()

	conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionBaseURL: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	version, err := conn.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "" {
		t.Fatalf("version = %q, want empty", version)
	}
}

func TestReachableRequiresSuccessOrRedirect(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{name: "success", status: http.StatusNoContent, want: true},
		{name: "redirect", status: http.StatusFound, want: true},
		{name: "not found", status: http.StatusNotFound, want: false},
		{name: "forbidden", status: http.StatusForbidden, want: false},
		{name: "server error", status: http.StatusInternalServerError, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			conn, err := NewVllmConnection(1, &inventory.Asset{}, &inventory.Config{
				Options: map[string]string{OptionBaseURL: server.URL},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := conn.Reachable(context.Background()); got != tt.want {
				t.Fatalf("reachable = %v, want %v", got, tt.want)
			}
		})
	}
}

//go:fix inline
func intPtr(v int) *int {
	return new(v)
}
