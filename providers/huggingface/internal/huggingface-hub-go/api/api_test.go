// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

func TestParseNextLink(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"no next rel", `<https://hf.co/api/models?cursor=a>; rel="prev"`, ""},
		{"single next", `<https://hf.co/api/models?cursor=a>; rel="next"`, "https://hf.co/api/models?cursor=a"},
		{"next among many", `<https://hf.co/api/models?cursor=z>; rel="prev", <https://hf.co/api/models?cursor=a>; rel="next"`, "https://hf.co/api/models?cursor=a"},
		{"unquoted rel", `<https://hf.co/next>; rel=next`, "https://hf.co/next"},
		{"malformed no brackets", `https://hf.co/next; rel="next"`, ""},
		{"malformed no rel param", `<https://hf.co/next>`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseNextLink(tt.header))
		})
	}
}

func TestEscapeRepoID(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B"},
		{"gpt2", "gpt2"},
		{"owner/name with space", "owner/name%20with%20space"},
		{"owner/sub/name", "owner/sub%2Fname"}, // only the first "/" is a separator
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, escapeRepoID(tt.in))
		})
	}
}

func TestBuildURL(t *testing.T) {
	a := NewAPI("https://huggingface.co", http.DefaultClient, "")

	u, err := a.buildURL("models?author=acme&limit=1000")
	require.NoError(t, err)
	assert.Equal(t, "https://huggingface.co/api/models?author=acme&limit=1000", u)

	u, err = a.buildURL("whoami-v2")
	require.NoError(t, err)
	assert.Equal(t, "https://huggingface.co/api/whoami-v2", u)
}

// TestListModelsPagination proves the list loop follows the rel="next" Link
// header across pages instead of truncating at the first page.
func TestListModelsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/models", r.URL.Path)
		switch r.URL.Query().Get("cursor") {
		case "":
			// First page: two models plus a link to the next page.
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/models?cursor=page2>; rel="next"`, srv.URL))
			_, _ = w.Write([]byte(`[{"id":"acme/one"},{"id":"acme/two"}]`))
		case "page2":
			// Last page: one model, no Link header.
			_, _ = w.Write([]byte(`[{"id":"acme/three"}]`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	opts := models.NewModelListOptions()
	opts.Author = "acme"

	list, err := a.ListModels(context.Background(), opts)
	require.NoError(t, err)
	require.Len(t, list.Models, 3)
	assert.Equal(t, "acme/one", list.Models[0].ID)
	assert.Equal(t, "acme/three", list.Models[2].ID)
}

// TestListModelsStopsOnRepeatedCursor guards against an infinite loop if the
// server ever returns a Link header pointing back at the same page.
func TestListModelsStopsOnRepeatedCursor(t *testing.T) {
	var srv *httptest.Server
	calls := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// Always point "next" at the same absolute URL.
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/models?cursor=loop>; rel="next"`, srv.URL))
		_, _ = w.Write([]byte(`[{"id":"acme/one"}]`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	list, err := a.ListModels(context.Background(), models.NewModelListOptions())
	require.NoError(t, err)
	// First page ("models?...") then the repeated "cursor=loop" URL once; the
	// third visit is a repeat and breaks the loop.
	assert.Equal(t, 2, calls)
	assert.Len(t, list.Models, 2)
}

// TestListWebhooksPagination proves webhooks follow the same cursor pagination
// as the other list endpoints (the settings endpoint returns a bare array).
func TestListWebhooksPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/settings/webhooks", r.URL.Path)
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/settings/webhooks?cursor=page2>; rel="next"`, srv.URL))
			_, _ = w.Write([]byte(`[{"id":"w1"},{"id":"w2"}]`))
		case "page2":
			_, _ = w.Write([]byte(`[{"id":"w3"}]`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	hooks, err := a.ListWebhooks(context.Background(), models.NewWebhookListOptions())
	require.NoError(t, err)
	require.Len(t, hooks, 3)
	assert.Equal(t, "w3", hooks[2].ID)
}

func TestListModelsPropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	_, err := a.ListModels(context.Background(), models.NewModelListOptions())
	require.Error(t, err)
	// Error string must carry the "(status: 403)" suffix the resource layer
	// matches on to degrade gracefully.
	assert.Contains(t, err.Error(), "(status: 403)")
}
