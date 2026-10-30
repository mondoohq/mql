// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/together/connection"
)

// pagedClient returns a client whose v1/projects list serves pages[after],
// keyed by the after cursor of the request ("" for the first page).
func pagedClient(t *testing.T, pages map[string]string) (*together.Client, *int32) {
	t.Helper()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&calls, 1)
		body, ok := pages[r.URL.Query().Get("after")]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	conn, err := connection.NewTogetherConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OptionToken:   "not-a-real-key",
			connection.OptionBaseURL: srv.URL,
		},
	})
	require.NoError(t, err)
	return conn.Client(), &calls
}

func projectIDs(projects []together.Project) []string {
	ids := make([]string, 0, len(projects))
	for _, p := range projects {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestCollectPagesWalksEveryPage(t *testing.T) {
	// Synthetic: three pages chained by next_cursor; the last carries none.
	client, calls := pagedClient(t, map[string]string{
		"":   `{"data": [{"id": "proj-a"}, {"id": "proj-b"}], "next_cursor": "c1"}`,
		"c1": `{"data": [{"id": "proj-c"}], "next_cursor": "c2"}`,
		"c2": `{"data": [{"id": "proj-d"}]}`,
	})

	projects, err := collectPages(client.Projects.List(context.Background(), together.ProjectListParams{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"proj-a", "proj-b", "proj-c", "proj-d"}, projectIDs(projects))
	assert.Equal(t, int32(3), atomic.LoadInt32(calls))
}

func TestCollectPagesStopsOnAnEmptyPage(t *testing.T) {
	// Synthetic: a server that keeps a cursor on its final, empty page.
	client, calls := pagedClient(t, map[string]string{
		"":   `{"data": [{"id": "proj-a"}], "next_cursor": "c1"}`,
		"c1": `{"data": [], "next_cursor": "c2"}`,
	})

	projects, err := collectPages(client.Projects.List(context.Background(), together.ProjectListParams{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"proj-a"}, projectIDs(projects))
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestCollectPagesRejectsARepeatedCursor(t *testing.T) {
	// Synthetic: a server whose cursor never advances would otherwise page forever.
	client, calls := pagedClient(t, map[string]string{
		"":   `{"data": [{"id": "proj-a"}], "next_cursor": "c1"}`,
		"c1": `{"data": [{"id": "proj-b"}], "next_cursor": "c1"}`,
	})

	projects, err := collectPages(client.Projects.List(context.Background(), together.ProjectListParams{}))
	require.Error(t, err)
	assert.Nil(t, projects, "a list the walk could not finish must not be reported as complete")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestCollectPagesReportsAFailedPage(t *testing.T) {
	// Synthetic: the second page is refused (400, which the client does not retry).
	client, _ := pagedClient(t, map[string]string{
		"": `{"data": [{"id": "proj-a"}], "next_cursor": "missing"}`,
	})

	projects, err := collectPages(client.Projects.List(context.Background(), together.ProjectListParams{}))
	require.Error(t, err)
	assert.Nil(t, projects)
}
