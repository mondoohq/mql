// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GitHub's issues endpoint returns pull requests alongside issues: every pull
// request is an issue, and only the `pull_request` member distinguishes them.
// Leaving them in makes `openIssues` a mix of both, double counting work that
// `openMergeRequests` already reports.
func TestListIssuesRawExcludesPullRequests(t *testing.T) {
	body := `[
		{"number": 1, "title": "a real issue", "state": "open"},
		{"number": 2, "title": "a pull request", "state": "open",
		 "pull_request": {"url": "https://api.github.com/repos/o/r/pulls/2"}},
		{"number": 3, "title": "another issue", "state": "open"},
		{"number": 4, "title": "another pull request", "state": "open",
		 "pull_request": {"url": "https://api.github.com/repos/o/r/pulls/4"}}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v3/repos/o/r/issues", r.URL.Path)
		assert.Equal(t, "open", r.URL.Query().Get("state"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	issues, err := listIssuesRaw(context.Background(), newTestGithubClient(t, server), "o", "r", "open")
	require.NoError(t, err)

	numbers := []int{}
	for _, i := range issues {
		numbers = append(numbers, i.GetNumber())
	}
	assert.Equal(t, []int{1, 3}, numbers, "pull requests must not be reported as issues")
}

// The state filter is passed through and pagination still collects every page.
func TestListIssuesRawPaginatesClosedIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "closed", r.URL.Query().Get("state"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(
				`<http://%s/api/v3/repos/o/r/issues?state=closed&page=2>; rel="next"`, r.Host))
			fmt.Fprint(w, `[{"number": 10, "state": "closed"},
			                {"number": 11, "state": "closed",
			                 "pull_request": {"url": "https://api.github.com/repos/o/r/pulls/11"}}]`)
		case "2":
			fmt.Fprint(w, `[{"number": 12, "state": "closed"}]`)
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	issues, err := listIssuesRaw(context.Background(), newTestGithubClient(t, server), "o", "r", "closed")
	require.NoError(t, err)

	numbers := []int{}
	for _, i := range issues {
		numbers = append(numbers, i.GetNumber())
	}
	assert.Equal(t, []int{10, 12}, numbers)
}

// A repository whose issues endpoint returns only pull requests reports no
// issues rather than reporting the pull requests.
func TestListIssuesRawAllPullRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"number": 5, "pull_request": {"url": "u"}}]`)
	}))
	defer server.Close()

	issues, err := listIssuesRaw(context.Background(), newTestGithubClient(t, server), "o", "r", "open")
	require.NoError(t, err)
	assert.Empty(t, issues)
}
