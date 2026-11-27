// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestGithubClient returns a github client retargeted at the given test
// server, mimicking how connection.go uses WithEnterpriseURLs.
func newTestGithubClient(t *testing.T, server *httptest.Server) *github.Client {
	t.Helper()
	base, err := url.Parse(server.URL + "/")
	require.NoError(t, err)
	client, err := github.NewClient(github.WithEnterpriseURLs(base.String(), base.String()))
	require.NoError(t, err)
	return client
}

func TestListRunnersRaw(t *testing.T) {
	page1 := `{
		"total_count": 3,
		"runners": [
			{"id": 1, "name": "runner-a", "os": "linux", "status": "online", "busy": false, "ephemeral": true, "architecture": "x64",
			 "labels": [{"id": 10, "name": "self-hosted", "type": "read-only"}]},
			{"id": 2, "name": "runner-b", "os": "linux", "status": "online", "busy": true, "ephemeral": false, "architecture": "arm64",
			 "labels": [{"id": 11, "name": "linux", "type": "read-only"}]}
		]
	}`
	page2 := `{
		"total_count": 3,
		"runners": [
			{"id": 3, "name": "runner-c", "os": "linux", "status": "offline", "busy": false}
		]
	}`

	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.RequestURI())
		// WithEnterpriseURLs configures /api/v3/ as the base for relative URLs,
		// so we receive "/api/v3/orgs/test-org/actions/runners?per_page=100&page=N".
		if !strings.HasPrefix(r.URL.Path, "/api/v3/orgs/test-org/actions/runners") {
			http.NotFound(w, r)
			return
		}
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			// advertise page 2 via Link header so go-github sets resp.NextPage.
			next := fmt.Sprintf(`<%s/api/v3/orgs/test-org/actions/runners?per_page=100&page=2>; rel="next"`, srvURL(r))
			w.Header().Set("Link", next)
			fmt.Fprint(w, page1)
		case "2":
			fmt.Fprint(w, page2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestGithubClient(t, srv)
	got, err := listRunnersRaw(context.Background(), client, "orgs/test-org/actions/runners")
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Len(t, hits, 2, "expected pagination to fetch 2 pages")

	// architecture is read from the raw payload because go-github does not
	// expose it on its Runner struct.
	require.NotNil(t, got[0].Ephemeral)
	assert.True(t, *got[0].Ephemeral)
	require.NotNil(t, got[0].Architecture)
	assert.Equal(t, "x64", *got[0].Architecture)

	require.NotNil(t, got[1].Ephemeral)
	assert.False(t, *got[1].Ephemeral)
	require.NotNil(t, got[1].Architecture)
	assert.Equal(t, "arm64", *got[1].Architecture)

	// page-2 runner omits ephemeral/architecture entirely — pointers must stay nil
	// (so MQL renders null rather than a misleading false/"").
	assert.Nil(t, got[2].Ephemeral)
	assert.Nil(t, got[2].Architecture)
	require.NotNil(t, got[2].Name)
	assert.Equal(t, "runner-c", *got[2].Name)
}

func TestListRunnersRawSinglePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total_count": 0, "runners": []}`)
	}))
	defer srv.Close()

	client := newTestGithubClient(t, srv)
	got, err := listRunnersRaw(context.Background(), client, "orgs/test-org/actions/runners")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// srvURL reconstructs the base URL of the test server from the inbound request,
// so the Link header we emit points back at ourselves regardless of the
// ephemeral port httptest picked.
func srvURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// Synthetic: version and runner_group_id as the runner list documents them.
func TestListRunnersRawVersionAndGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total_count": 2, "runners": [
			{"id": 1, "name": "a", "runner_group_id": 7, "version": "2.329.0"},
			{"id": 2, "name": "b"}
		]}`)
	}))
	defer srv.Close()

	got, err := listRunnersRaw(context.Background(), newTestGithubClient(t, srv), "orgs/test-org/actions/runners")
	require.NoError(t, err)
	require.Len(t, got, 2)

	require.NotNil(t, got[0].Version)
	assert.Equal(t, "2.329.0", *got[0].Version)
	require.NotNil(t, got[0].RunnerGroupID)
	assert.Equal(t, int64(7), *got[0].RunnerGroupID)

	assert.Nil(t, got[1].Version, "an unreported version stays null")
	assert.Nil(t, got[1].RunnerGroupID)
}

// Synthetic: the listing scopes runnersToMql receives.
func TestRunnerScopeOwner(t *testing.T) {
	assert.Equal(t, "acme", runnerScopeOwner("orgs/acme"))
	assert.Equal(t, "acme", runnerScopeOwner("repos/acme/widgets"))
	assert.Equal(t, "", runnerScopeOwner("users/acme"))
	assert.Equal(t, "", runnerScopeOwner("orgs"))
	assert.Equal(t, "", runnerScopeOwner(""))
}

// Synthetic: a runner the listing reported no group for has no group to
// resolve, and must not reach for the organization.
func TestRunnerGroupWithoutGroupID(t *testing.T) {
	runtime := prefetchRuntime()
	res, err := runnersToMql(runtime, "orgs/acme", []*ghRunnerExt{{ID: github.Ptr(int64(5)), Name: github.Ptr("a")}})
	require.NoError(t, err)
	require.Len(t, res, 1)

	runner := res[0].(*mqlGithubRunner)
	group, err := runner.runnerGroup()
	require.NoError(t, err)
	assert.Nil(t, group)
	assert.True(t, runner.RunnerGroup.IsNull())
}
