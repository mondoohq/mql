// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testClient points a real Client at an httptest server. Both base URLs are
// overridden so a test can exercise the runner endpoints through the same
// server as the API v2 ones.
func testClient(srv *httptest.Server) *Client {
	return &Client{
		httpClient:    srv.Client(),
		baseURL:       srv.URL,
		runnerBaseURL: srv.URL,
		token:         "test-token",
	}
}

// TestIsAccessDenied pins the error classifier. A permission problem
// degrades a field to null and lets the audit continue; a transport failure
// must not take that path, or a network blip is reported as "we looked and
// there was nothing to see" on data that was never read.
func TestIsAccessDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"401 unauthorized", &APIError{StatusCode: http.StatusUnauthorized, Path: "/me"}, true},
		{"403 forbidden", &APIError{StatusCode: http.StatusForbidden, Path: "/project/gh/example-org/example-project/settings"}, true},
		{"401 wrapped", fmt.Errorf("fetching settings: %w", &APIError{StatusCode: http.StatusUnauthorized}), true},
		{"403 double wrapped", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &APIError{StatusCode: http.StatusForbidden})), true},
		{"404 not found", &APIError{StatusCode: http.StatusNotFound}, false},
		{"429 rate limited", &APIError{StatusCode: http.StatusTooManyRequests}, false},
		{"500 server error", &APIError{StatusCode: http.StatusInternalServerError}, false},
		{"400 bad request", &APIError{StatusCode: http.StatusBadRequest}, false},
		{"nil", nil, false},
		{"plain error", errors.New("something went wrong"), false},
		// a timeout is the classic misread: it has nothing to do with
		// permissions, so it must surface as a failure
		{"wrapped deadline exceeded", fmt.Errorf("failed to call circleci api: %w", context.DeadlineExceeded), false},
		{"wrapped context canceled", fmt.Errorf("failed to call circleci api: %w", context.Canceled), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAccessDenied(tc.err); got != tc.want {
				t.Fatalf("IsAccessDenied: expected %v, got %v", tc.want, got)
			}
		})
	}
}

// TestIsAccessDeniedOnTransportError drives a real request against a closed
// listener, so the error is the genuine net.Error the http client produces
// rather than a hand-built stand-in.
func TestIsAccessDeniedOnTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := testClient(srv)
	c.httpClient = &http.Client{Timeout: 5 * time.Second}
	srv.Close()

	_, err := c.GetMe(context.Background())
	if err == nil {
		t.Fatal("expected a transport error against a closed listener")
	}

	// prove the test is exercising a network failure and not something else
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatalf("expected a net.Error, got %T: %v", err, err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("a transport failure must not carry an APIError, got status %d", apiErr.StatusCode)
	}
	if IsAccessDenied(err) {
		t.Fatalf("a transport failure must not read as access denied: %v", err)
	}
}

// TestIsAccessDeniedFromLiveStatusCodes checks the classifier end to end,
// through the APIError the client actually builds from a response.
func TestIsAccessDeniedFromLiveStatusCodes(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusNotFound, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, `{"message":"denied"}`)
			}))
			defer srv.Close()

			_, err := testClient(srv).GetMe(context.Background())
			if err == nil {
				t.Fatalf("expected an error for status %d", tc.status)
			}
			if got := IsAccessDenied(err); got != tc.want {
				t.Fatalf("status %d: expected IsAccessDenied %v, got %v (%v)", tc.status, tc.want, got, err)
			}
		})
	}
}

// TestVcsSlugPrefix pins the vcs_type to slug-prefix mapping. Every project
// and context lookup addresses CircleCI by a slug built from this prefix, so
// a wrong mapping does not fail: it discovers zero projects.
func TestVcsSlugPrefix(t *testing.T) {
	cases := []struct {
		name    string
		vcsType string
		want    string
	}{
		{"github", "github", "gh"},
		{"bitbucket", "bitbucket", "bb"},
		{"circleci native", "circleci", "circleci"},
		{"already abbreviated github", "gh", "gh"},
		{"already abbreviated bitbucket", "bb", "bb"},
		{"unknown vcs passes through", "gitlab", "gitlab"},
		{"empty", "", ""},
		// the mapping is exact, not case-insensitive; a mixed-case vcs_type
		// would pass through rather than silently mapping to gh
		{"mixed case is not mapped", "GitHub", "GitHub"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := VcsSlugPrefix(tc.vcsType); got != tc.want {
				t.Fatalf("VcsSlugPrefix(%q): expected %q, got %q", tc.vcsType, tc.want, got)
			}
		})
	}
}

// TestListProjectEnvVarsWalksPageTokens covers the paginated read end to
// end: the page-token parameter is threaded onto the next request, every
// page's records are accumulated, and an empty next_page_token terminates
// the walk. The guard against an endpoint that re-issues a token it already
// handed out lives in the resources package (pageWalker) and is tested
// there.
func TestListProjectEnvVarsWalksPageTokens(t *testing.T) {
	const projectSlug = "gh/example-org/example-project"

	var calls int
	var seenTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Circle-Token"); got != "test-token" {
			t.Errorf("missing/incorrect Circle-Token header: %q", got)
		}
		if want := "/project/" + projectSlug + "/envvar"; r.URL.Path != want {
			t.Errorf("expected path %q, got %q", want, r.URL.Path)
		}
		token := r.URL.Query().Get("page-token")
		seenTokens = append(seenTokens, token)

		w.Header().Set("Content-Type", "application/json")
		switch token {
		case "":
			io.WriteString(w, `{"items":[{"name":"FIRST"},{"name":"SECOND"}],"next_page_token":"page-b"}`)
		case "page-b":
			io.WriteString(w, `{"items":[{"name":"THIRD"}],"next_page_token":"page-c"}`)
		case "page-c":
			// an empty token terminates the walk
			io.WriteString(w, `{"items":[{"name":"FOURTH"}],"next_page_token":""}`)
		default:
			t.Errorf("unexpected page token: %q", token)
			io.WriteString(w, `{"items":[],"next_page_token":""}`)
		}
	}))
	defer srv.Close()

	client := testClient(srv)

	// mirrors the production walk in resources/project.go
	var names []string
	pageToken := ""
	for {
		resp, err := client.ListProjectEnvVars(context.Background(), projectSlug, pageToken)
		if err != nil {
			t.Fatalf("ListProjectEnvVars: %v", err)
		}
		for _, v := range resp.Items {
			names = append(names, v.Name)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	if calls != 3 {
		t.Fatalf("expected 3 page requests, got %d", calls)
	}
	wantTokens := []string{"", "page-b", "page-c"}
	if fmt.Sprint(seenTokens) != fmt.Sprint(wantTokens) {
		t.Fatalf("expected page tokens %v, got %v", wantTokens, seenTokens)
	}
	want := []string{"FIRST", "SECOND", "THIRD", "FOURTH"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("expected %v, got %v", want, names)
	}
}

// TestListProjectEnvVarsOmitsEmptyPageToken pins the first-page request: an
// empty token must not be sent as page-token=, which some endpoints treat as
// an invalid cursor rather than "start at the beginning".
func TestListProjectEnvVarsOmitsEmptyPageToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["page-token"]; ok {
			t.Errorf("page-token must be omitted on the first request, got %q", r.URL.RawQuery)
		}
		io.WriteString(w, `{"items":[{"name":"ONLY"}],"next_page_token":""}`)
	}))
	defer srv.Close()

	resp, err := testClient(srv).ListProjectEnvVars(context.Background(), "gh/example-org/example-project", "")
	if err != nil {
		t.Fatalf("ListProjectEnvVars: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Name != "ONLY" {
		t.Fatalf("expected one item named ONLY, got %+v", resp.Items)
	}
	if resp.NextPageToken != "" {
		t.Fatalf("expected an empty next_page_token, got %q", resp.NextPageToken)
	}
}

// TestListPipelinesSendsOrgSlug pins the query parameters of the endpoint
// project discovery depends on. A wrong parameter name is answered with a
// valid empty page, so the failure mode is discovering nothing.
func TestListPipelinesSendsOrgSlug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("org-slug"); got != "gh/example-org" {
			t.Errorf("expected org-slug gh/example-org, got %q", got)
		}
		if got := q.Get("page-token"); got != "page-b" {
			t.Errorf("expected page-token page-b, got %q", got)
		}
		io.WriteString(w, `{"items":[{"id":"00000000-0000-0000-0000-000000000001","project_slug":"gh/example-org/example-project"}],"next_page_token":""}`)
	}))
	defer srv.Close()

	resp, err := testClient(srv).ListPipelines(context.Background(), "gh/example-org", "page-b")
	if err != nil {
		t.Fatalf("ListPipelines: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].ProjectSlug != "gh/example-org/example-project" {
		t.Fatalf("expected one pipeline carrying a project_slug, got %+v", resp.Items)
	}
}

// TestListContextsSendsOwnerParams pins the owner-id/owner-type pair. The
// endpoint requires both, and an omitted owner-type is rejected rather than
// defaulted.
func TestListContextsSendsOwnerParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("owner-id"); got != "00000000-0000-0000-0000-000000000009" {
			t.Errorf("unexpected owner-id: %q", got)
		}
		if got := q.Get("owner-type"); got != "organization" {
			t.Errorf("expected owner-type organization, got %q", got)
		}
		io.WriteString(w, `{"items":[{"id":"00000000-0000-0000-0000-00000000000a","name":"example-context","created_at":"2026-01-02T03:04:05Z"}],"next_page_token":""}`)
	}))
	defer srv.Close()

	resp, err := testClient(srv).ListContexts(context.Background(), "00000000-0000-0000-0000-000000000009", "")
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Name != "example-context" {
		t.Fatalf("expected one context named example-context, got %+v", resp.Items)
	}
}

// TestGetProjectSettingsUnwrapsAdvanced covers the one accessor that reshapes
// its response: the advanced block is returned unwrapped, and every project
// posture field reads through it.
func TestGetProjectSettingsUnwrapsAdvanced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/project/gh/example-org/example-project/settings"; r.URL.Path != want {
			t.Errorf("expected path %q, got %q", want, r.URL.Path)
		}
		io.WriteString(w, `{"advanced":{"forks_receive_secret_env_vars":false,"disable_ssh":true}}`)
	}))
	defer srv.Close()

	got, err := testClient(srv).GetProjectSettings(context.Background(), "gh/example-org/example-project")
	if err != nil {
		t.Fatalf("GetProjectSettings: %v", err)
	}
	if got.ForksReceiveSecretEnvVars == nil || *got.ForksReceiveSecretEnvVars != false {
		t.Fatalf("forks_receive_secret_env_vars: expected a reported false, got %v", got.ForksReceiveSecretEnvVars)
	}
	if got.DisableSsh == nil || *got.DisableSsh != true {
		t.Fatalf("disable_ssh: expected true, got %v", got.DisableSsh)
	}
	// a flag the response omitted must stay null rather than reading false
	if got.BuildForkPrs != nil {
		t.Fatalf("build_fork_prs was not in the response and must stay nil, got %v", *got.BuildForkPrs)
	}
}

// TestListRunnerResourceClassesUsesRunnerBaseURL pins the second host. The
// runner API is served from a different base URL, so a call routed to the
// API v2 host would 404 and report no runners.
func TestListRunnerResourceClassesUsesRunnerBaseURL(t *testing.T) {
	var hits int
	runnerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/runner/resource" {
			t.Errorf("unexpected runner path: %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("namespace"); got != "example-org" {
			t.Errorf("expected namespace example-org, got %q", got)
		}
		io.WriteString(w, `{"items":[{"id":"00000000-0000-0000-0000-00000000000b","resource_class":"example-org/example-class","description":"example"}]}`)
	}))
	defer runnerSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("runner call must not reach the api v2 host: %q", r.URL.Path)
	}))
	defer apiSrv.Close()

	c := &Client{
		httpClient:    runnerSrv.Client(),
		baseURL:       apiSrv.URL,
		runnerBaseURL: runnerSrv.URL,
		token:         "test-token",
	}

	resp, err := c.ListRunnerResourceClasses(context.Background(), "example-org")
	if err != nil {
		t.Fatalf("ListRunnerResourceClasses: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 request to the runner host, got %d", hits)
	}
	if len(resp.Items) != 1 || resp.Items[0].ResourceClass != "example-org/example-class" {
		t.Fatalf("unexpected resource classes: %+v", resp.Items)
	}
}

// TestAPIErrorMessageCarriesContext keeps the error text useful: a 403
// surfaced without its path leaves the reader guessing which endpoint the
// token cannot reach.
func TestAPIErrorMessageCarriesContext(t *testing.T) {
	err := &APIError{StatusCode: http.StatusForbidden, Path: "/project/gh/example-org/example-project/settings", Body: `{"message":"denied"}`}
	msg := err.Error()
	for _, want := range []string{"403", "/project/gh/example-org/example-project/settings", "denied"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message %q is missing %q", msg, want)
		}
	}
}
