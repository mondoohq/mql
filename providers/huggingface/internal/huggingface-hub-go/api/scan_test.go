// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

// The three repository kinds are served under their own path segment. Asking
// for a dataset under the models segment returns "not found", which the
// resource layer turns into a null verdict, so the segment has to be right.
func TestGetRepoScanPath(t *testing.T) {
	tests := []struct {
		repoType models.RepoType
		repoID   string
		wantPath string
	}{
		{models.RepoTypeModel, "mcpotato/42-eicar-street", "/api/models/mcpotato/42-eicar-street/scan"},
		{models.RepoTypeDataset, "rajpurkar/squad", "/api/datasets/rajpurkar/squad/scan"},
		{models.RepoTypeSpace, "enzostvs/deepsite", "/api/spaces/enzostvs/deepsite/scan"},
	}
	for _, tt := range tests {
		t.Run(string(tt.repoType), func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				_, _ = w.Write([]byte(`{"scansDone":true,"filesWithIssues":[{"path":"x.pkl","level":"unsafe"}]}`))
			}))
			defer srv.Close()

			a := NewAPI(srv.URL, srv.Client(), "")
			scan, err := a.GetRepoScan(context.Background(), tt.repoType, tt.repoID)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, gotPath)
			require.Len(t, scan.FilesWithIssues, 1)
			assert.Equal(t, "unsafe", scan.FilesWithIssues[0].Level)
		})
	}
}

// A repository the token cannot see answers 401, not 404. The error has to
// carry the "(status: 401)" suffix the resource layer matches on to resolve the
// field to null instead of reporting a clean scan.
func TestGetRepoScanDeniedCarriesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid username or password."}`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	_, err := a.GetRepoScan(context.Background(), models.RepoTypeModel, "acme/private")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "(status: 401)")
}

// setExpand has to put every requested field on the wire under the repeated
// "expand[]" key. Dropping the call leaves the request unexpanded, and the Hub
// then omits gated, disabled, sha and lastModified from the response entirely.
func TestSetExpandWritesRepeatedKey(t *testing.T) {
	params := url.Values{}
	setExpand(params, []string{"gated", "sha", "runtime"}, false)

	assert.Equal(t, []string{"gated", "sha", "runtime"}, params["expand[]"])
	assert.Empty(t, params.Get("full"), "expand[] makes full redundant; the Hub ignores it")
}

// With no expand list the caller's full flag is still honored, so the option
// keeps working for any caller that does not name fields.
func TestSetExpandFallsBackToFull(t *testing.T) {
	params := url.Values{}
	setExpand(params, nil, true)
	assert.Equal(t, "true", params.Get("full"))
	assert.Empty(t, params["expand[]"])

	bare := url.Values{}
	setExpand(bare, nil, false)
	assert.Empty(t, bare.Get("full"))
	assert.Empty(t, bare["expand[]"])
}

// The list callers must actually send the expand set their options carry. This
// is the wire-level half of the models package's coverage test: there the list
// is checked for completeness, here it is checked for arriving at the server.
func TestListSpacesSendsExpand(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()["expand[]"]
		// Answer with the restricted shape expand[] actually produces.
		_, _ = w.Write([]byte(`[{"id":"acme/app","sdk":"docker","region":"eu",` +
			`"runtime":{"stage":"RUNNING","devMode":true}}]`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	list, err := a.ListSpaces(context.Background(), models.NewSpaceListOptions())
	require.NoError(t, err)

	assert.ElementsMatch(t, models.SpaceListExpand, got)
	assert.Contains(t, got, "runtime", "without this the Space runtime block is never returned")

	require.Len(t, list.Spaces, 1)
	require.NotNil(t, list.Spaces[0].Runtime)
	require.NotNil(t, list.Spaces[0].Runtime.DevMode)
	assert.True(t, *list.Spaces[0].Runtime.DevMode)
	assert.Equal(t, "eu", list.Spaces[0].Region)
}

func TestListModelsSendsExpand(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()["expand[]"]
		_, _ = w.Write([]byte(`[{"id":"meta-llama/Llama-3.1-8B","gated":"manual","disabled":false}]`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	list, err := a.ListModels(context.Background(), models.NewModelListOptions())
	require.NoError(t, err)

	assert.ElementsMatch(t, models.ModelListExpand, got)
	assert.Contains(t, got, "gated", "without this every listed model reads as ungated")

	require.Len(t, list.Models, 1)
	assert.Equal(t, "manual", list.Models[0].Gated.Mode)
	// modelId is not expandable, so the list restores it from id.
	assert.Equal(t, "meta-llama/Llama-3.1-8B", list.Models[0].ModelID)
}

func TestListDatasetsSendsExpand(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()["expand[]"]
		_, _ = w.Write([]byte(`[{"id":"acme/ds","gated":"auto","downloadsAllTime":42}]`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	list, err := a.ListDatasets(context.Background(), models.NewDatasetListOptions())
	require.NoError(t, err)

	assert.ElementsMatch(t, models.DatasetListExpand, got)
	require.Len(t, list.Datasets, 1)
	assert.Equal(t, "auto", list.Datasets[0].Gated.Mode)
	assert.Equal(t, 42, list.Datasets[0].DownloadsAllTime)
}
