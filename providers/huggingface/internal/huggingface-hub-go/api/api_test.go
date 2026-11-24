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

// Synthetic: two pages shaped after the Inference Endpoints v2 OpenAPI
// document (EndpointWithStatusList); no live account was checked.
//
// The list nests the model and the status as objects and pages with a
// nextCursor in the body. Decoding them as flat strings failed on any account
// with an endpoint, and stopping after one page dropped the rest.
func TestListInferenceEndpointsPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/endpoint/acme", r.URL.Path)
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{"items":[{"name":"one","type":"authenticated",
				"model":{"repository":"acme/llm","framework":"pytorch","image":{}},
				"status":{"state":"running","url":"https://one.endpoints.huggingface.cloud",
					"createdAt":"2026-01-02T03:04:05Z","updatedAt":"2026-02-03T04:05:06Z"}}],
				"nextCursor":"page2","totalItems":2}`))
		case "page2":
			_, _ = w.Write([]byte(`{"items":[{"name":"two","model":{"repository":"acme/other"},
				"status":{"state":"scaledToZero"}}],"nextCursor":null,"totalItems":2}`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	a.endpointsBaseURL = srv.URL
	list, err := a.ListInferenceEndpoints(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, list.Endpoints, 2)
	assert.Equal(t, "one", list.Endpoints[0].Name)
	assert.Equal(t, "acme/llm", list.Endpoints[0].Model.Repository)
	assert.Equal(t, "pytorch", list.Endpoints[0].Model.Framework)
	assert.Equal(t, "running", list.Endpoints[0].Status.State)
	assert.Equal(t, "https://one.endpoints.huggingface.cloud", list.Endpoints[0].Status.URL)
	assert.Equal(t, "2026-01-02T03:04:05Z", list.Endpoints[0].Status.CreatedAt)
	assert.Equal(t, "scaledToZero", list.Endpoints[1].Status.State)
}

// Synthetic: a server that keeps answering with the same cursor; no live
// account showed this. The walk must stop with an error, not loop.
func TestListInferenceEndpointsStopsOnRepeatedCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"name":"one"}],"nextCursor":"same","totalItems":9}`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	a.endpointsBaseURL = srv.URL
	_, err := a.ListInferenceEndpoints(context.Background(), "acme")
	require.Error(t, err)
}

// Synthetic: a first page with no items that still names a next page; no live
// account showed this. The cursor alone decides whether to continue, so the
// endpoint on the second page must not be dropped.
func TestListInferenceEndpointsFollowsCursorPastEmptyPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{"items":[],"nextCursor":"page2","totalItems":1}`))
		case "page2":
			_, _ = w.Write([]byte(`{"items":[{"name":"late"}],"nextCursor":null,"totalItems":1}`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	a.endpointsBaseURL = srv.URL
	list, err := a.ListInferenceEndpoints(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, list.Endpoints, 1)
	assert.Equal(t, "late", list.Endpoints[0].Name)
}

// Synthetic: two pages of members linked by an RFC 8288 Link header, as the
// Hub OpenAPI document describes for GET /api/organizations/{name}/members; no
// live account was checked.
func TestListOrgMembersPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/organizations/acme/members", r.URL.Path)
		switch r.URL.Query().Get("cursor") {
		case "":
			assert.Equal(t, "true", r.URL.Query().Get("includeExternal"))
			assert.Equal(t, "1000", r.URL.Query().Get("limit"))
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/organizations/acme/members?cursor=p2>; rel="next"`, srv.URL))
			_, _ = w.Write([]byte(`[{"_id":"m1","user":"alice","role":"admin"}]`))
		case "p2":
			_, _ = w.Write([]byte(`[{"_id":"m2","user":"bob","role":"read"}]`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	members, err := a.ListOrgMembers(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "alice", members[0].User)
	assert.Equal(t, "bob", members[1].User)
}

// Synthetic: two pages of member tokens, as the Hub OpenAPI document describes
// for GET /api/organizations/{name}/settings/tokens; no live account was
// checked.
func TestListOrgMemberTokensPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/organizations/acme/settings/tokens", r.URL.Path)
		switch r.URL.Query().Get("cursor") {
		case "":
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/organizations/acme/settings/tokens?cursor=bbbbbbbbbbbbbbbbbbbbbbbb>; rel="next"`, srv.URL))
			_, _ = w.Write([]byte(`[{"_id":"t1","role":"read","owner":{"_id":"m1","name":"alice"}}]`))
		case "bbbbbbbbbbbbbbbbbbbbbbbb":
			_, _ = w.Write([]byte(`[{"_id":"t2","role":"write","owner":{"_id":"m2","name":"bob"}}]`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	tokens, err := a.ListOrgMemberTokens(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	assert.Equal(t, "t1", tokens[0].ID)
	assert.Equal(t, "t2", tokens[1].ID)
}

// Synthetic: a server that refuses a plan-gated organization endpoint; no live
// account was checked. The status suffix is what the resource layer reads.
func TestOrgSettingsPropagateStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/organizations/acme/settings/network-security", r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"requires a Team or Enterprise plan"}`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	_, err := a.GetOrgNetworkSecurity(context.Background(), "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "(status: 403)")
}

// Synthetic: trusted publishers on a dataset; no live account was checked.
// The repository type and both id segments must land in the path.
func TestListTrustedPublishersPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/datasets/acme/data/settings/trusted-publishers", r.URL.Path)
		_, _ = w.Write([]byte(`[{"_id":"p1","issuerUrl":"https://token.actions.githubusercontent.com","claims":{},"createdAt":"2026-01-01T00:00:00Z"}]`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	pubs, err := a.ListTrustedPublishers(context.Background(), models.RepoTypeDataset, "acme/data")
	require.NoError(t, err)
	require.Len(t, pubs, 1)
	assert.Equal(t, "p1", pubs[0].ID)
}

// Synthetic: two pages of accepted access requests on a gated model, as the
// Hub OpenAPI document describes; no live account was checked.
func TestListAccessRequestsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/models/acme/llm/user-access-request/accepted", r.URL.Path)
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/models/acme/llm/user-access-request/accepted?cursor=p2>; rel="next"`, srv.URL))
			_, _ = w.Write([]byte(`[{"requestId":"r1","status":"accepted","timestamp":"2026-01-01T00:00:00Z"}]`))
		case "p2":
			_, _ = w.Write([]byte(`[{"requestId":"r2","status":"accepted","timestamp":"2026-01-02T00:00:00Z"}]`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	reqs, err := a.ListAccessRequests(context.Background(), models.RepoTypeModel, "acme/llm", models.AccessRequestAccepted)
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	assert.Equal(t, "r2", reqs[1].RequestID)
}

// Synthetic: a server whose next link points back at the page it served; no
// live account showed this. The walk must stop instead of looping.
func TestListAllPagesStopsOnRepeatedLink(t *testing.T) {
	var srv *httptest.Server
	calls := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/organizations/acme/members?cursor=loop>; rel="next"`, srv.URL))
		_, _ = w.Write([]byte(`[{"_id":"m1"}]`))
	}))
	defer srv.Close()

	a := NewAPI(srv.URL, srv.Client(), "")
	members, err := a.ListOrgMembers(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Len(t, members, 2)
}
