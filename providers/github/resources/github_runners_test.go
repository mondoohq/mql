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

	"github.com/google/go-github/v92/github"
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
