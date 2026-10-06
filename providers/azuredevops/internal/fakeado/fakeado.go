// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package fakeado is an in-process stand-in for the Azure DevOps REST API.
//
// It serves JSON documents modelled on the documented API, from the embedded
// testdata folder, for one fabricated organization. They are not recordings of
// a live organization. Every name, id and address in the fixtures is invented,
// and the git objectId and commitId values are GUID-shaped where the real API
// returns 40-character SHA-1 hashes. Tests start a server with New, point a
// connection at its URL with the api-endpoint option and never touch the
// network.
package fakeado

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

//go:embed testdata/*.json
var fixtures embed.FS

const (
	// Org is the only organization the server knows.
	Org = "mondoo-ado-scan-test"
	// BearerToken is the Entra access token the server accepts.
	BearerToken = "fake-entra-access-token"
	// PAT is the personal access token the server accepts as a Basic password.
	PAT = "fake-personal-access-token"

	// APIVersion is the only api-version the server answers to on versioned
	// calls, so a client that forgets it fails a test.
	APIVersion = "7.1"
)

// Fabricated ids of the fixture repositories.
const (
	RepoIacID     = "2b000000-0000-4000-8000-000000000001"
	RepoAppID     = "2b000000-0000-4000-8000-000000000002"
	RepoEmptyID   = "2b000000-0000-4000-8000-000000000003"
	RepoRetiredID = "2b000000-0000-4000-8000-000000000004"
	RepoIacSpace  = "2b000000-0000-4000-8000-000000000005"
	RepoDocsID    = "2b000000-0000-4000-8000-000000000006"
)

// projectRepos maps a project to its repository list fixture. A project that is
// missing from the map is not readable and answers 403.
var projectRepos = map[string]string{
	"scan-test":   "repos_scan-test.json",
	"scan test":   "repos_scan-test-space.json",
	"legacy-apps": "repos_legacy-apps.json",
}

// repoItems maps a repository id to its tree fixture. The empty repository has
// no entry and answers 404 VS403403.
var repoItems = map[string]string{
	RepoIacID:     "items_iac.json",
	RepoAppID:     "items_app.json",
	RepoRetiredID: "items_retired.json",
	RepoIacSpace:  "items_iac_space.json",
	RepoDocsID:    "items_docs.json",
}

const signInPage = "<html><head><title>Sign In</title></head><body>Sign in to continue</body></html>"

// Server is a running fake.
type Server struct {
	*httptest.Server

	mu          sync.Mutex
	requests    []string
	throttles   []*throttle
	deniedItems map[string]bool
	hiddenRepos map[string]bool
}

type throttle struct {
	suffix     string
	left       int
	retryAfter string
}

// New starts a server and stops it when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// Requests lists the "path?query" of every request so far, in arrival order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// ThrottleNext answers the next n requests whose path ends in suffix with
// HTTP 429. The suffix is matched against the decoded URL path ("scan test",
// not "scan%20test"), and the query string is ignored. A non-empty retryAfter
// is sent as the Retry-After header.
func (s *Server) ThrottleNext(suffix string, n int, retryAfter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.throttles = append(s.throttles, &throttle{suffix: suffix, left: n, retryAfter: retryAfter})
}

// DenyItems makes the tree of one repository answer HTTP 403, as it does for a
// principal that may list a repository but not read its contents.
func (s *Server) DenyItems(repoID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deniedItems == nil {
		s.deniedItems = map[string]bool{}
	}
	s.deniedItems[repoID] = true
}

func (s *Server) itemsDenied(repoID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deniedItems[repoID]
}

// HideRepositories makes the repository list of one project answer HTTP 404
// with the TF401019 error, as Azure DevOps often does for a project the
// principal cannot see instead of the 403 a project it can see would give.
func (s *Server) HideRepositories(project string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hiddenRepos == nil {
		s.hiddenRepos = map[string]bool{}
	}
	s.hiddenRepos[project] = true
}

func (s *Server) repositoriesHidden(project string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hiddenRepos[project]
}

func (s *Server) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.URL.Path+"?"+r.URL.RawQuery)
}

func (s *Server) throttled(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, th := range s.throttles {
		if th.left > 0 && strings.HasSuffix(r.URL.Path, th.suffix) {
			th.left--
			if th.retryAfter != "" {
				w.Header().Set("Retry-After", th.retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"TF400733: The request has been canceled: Request was blocked due to exceeding usage of resource."}`))
			return true
		}
	}
	return false
}

func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if h == "Bearer "+BearerToken {
		return true
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+PAT))
	return h == want
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.record(r)

	if !s.authorized(r) {
		// Azure DevOps answers some bad tokens with its HTML sign-in page and a
		// 203, not with a 401.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		_, _ = w.Write([]byte(signInPage))
		return
	}
	if s.throttled(w, r) {
		return
	}

	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segs) < 2 || segs[0] != Org {
		serveFixture(w, http.StatusNotFound, "error_forbidden.json")
		return
	}
	segs = segs[1:]

	// connectionData is the one call that takes no api-version.
	if len(segs) == 2 && segs[0] == "_apis" && segs[1] == "connectionData" {
		serveFixture(w, http.StatusOK, "connection_data.json")
		return
	}
	if r.URL.Query().Get("api-version") != APIVersion {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "VS402337: The requested api-version is missing or not supported"})
		return
	}

	switch {
	case len(segs) == 2 && segs[0] == "_apis" && segs[1] == "projects":
		s.projects(w, r)
	case len(segs) == 3 && segs[0] == "_apis" && segs[1] == "projects":
		s.project(w, segs[2])
	case len(segs) == 4 && segs[1] == "_apis" && segs[2] == "git" && segs[3] == "repositories":
		s.repositories(w, segs[0])
	case len(segs) == 5 && segs[1] == "_apis" && segs[2] == "git" && segs[3] == "repositories":
		s.repository(w, segs[0], segs[4])
	case len(segs) == 6 && segs[1] == "_apis" && segs[2] == "git" && segs[3] == "repositories" && segs[5] == "items":
		s.items(w, segs[0], segs[4])
	default:
		serveFixture(w, http.StatusNotFound, "error_forbidden.json")
	}
}

// projects serves two pages. The first one names the second in the
// x-ms-continuationtoken header, as the real service does.
func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("x-ratelimit-cost", "2")
	if r.URL.Query().Get("continuationToken") == "" {
		w.Header().Set("x-ms-continuationtoken", "2")
		serveFixture(w, http.StatusOK, "projects_page1.json")
		return
	}
	serveFixture(w, http.StatusOK, "projects_page2.json")
}

// project serves one project, found by name or id on either page of the list.
func (s *Server) project(w http.ResponseWriter, nameOrID string) {
	for _, file := range []string{"projects_page1.json", "projects_page2.json"} {
		var list struct {
			Value []json.RawMessage `json:"value"`
		}
		mustDecode(file, &list)
		for _, raw := range list.Value {
			var head struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &head); err == nil && (head.ID == nameOrID || head.Name == nameOrID) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(raw)
				return
			}
		}
	}
	serveFixture(w, http.StatusNotFound, "error_forbidden.json")
}

func (s *Server) repositories(w http.ResponseWriter, project string) {
	if s.repositoriesHidden(project) {
		serveFixture(w, http.StatusNotFound, "error_forbidden.json")
		return
	}
	file, ok := projectRepos[project]
	if !ok {
		serveFixture(w, http.StatusForbidden, "error_forbidden.json")
		return
	}
	w.Header().Set("x-ratelimit-cost", "1")
	serveFixture(w, http.StatusOK, file)
}

func (s *Server) repository(w http.ResponseWriter, project, repo string) {
	file, ok := projectRepos[project]
	if !ok {
		serveFixture(w, http.StatusForbidden, "error_forbidden.json")
		return
	}
	var list struct {
		Value []json.RawMessage `json:"value"`
	}
	mustDecode(file, &list)
	for _, raw := range list.Value {
		var head struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &head); err == nil && (head.ID == repo || head.Name == repo) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
			return
		}
	}
	serveFixture(w, http.StatusNotFound, "error_forbidden.json")
}

func (s *Server) items(w http.ResponseWriter, project, repoID string) {
	if _, ok := projectRepos[project]; !ok {
		serveFixture(w, http.StatusForbidden, "error_forbidden.json")
		return
	}
	if s.itemsDenied(repoID) {
		serveFixture(w, http.StatusForbidden, "error_forbidden.json")
		return
	}
	file, ok := repoItems[repoID]
	if !ok {
		serveFixture(w, http.StatusNotFound, "error_empty_repo.json")
		return
	}
	w.Header().Set("x-ratelimit-cost", "3")
	serveFixture(w, http.StatusOK, file)
}

func serveFixture(w http.ResponseWriter, status int, name string) {
	data, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		http.Error(w, "missing fixture "+name+": "+strconv.Quote(err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func mustDecode(name string, out any) {
	data, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		panic(err)
	}
}
