// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mistralai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pagedServer serves File objects split into pages. It optionally sets
// has_more and/or total on the envelope so each pagination-termination path can
// be exercised independently. perPage controls how many items a single page
// returns, which lets us simulate a server that caps page_size below the
// requested value.
type pagedServer struct {
	total       int  // total items available
	perPage     int  // items returned per page (server-side cap)
	sendHasMore bool // include has_more in the envelope
	sendTotal   bool // include total in the envelope
	requests    int  // number of pages actually requested
}

func (s *pagedServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.requests++
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		require.NoError(t, err)

		start := page * s.perPage
		data := []File{}
		for i := start; i < start+s.perPage && i < s.total; i++ {
			data = append(data, File{ID: fmt.Sprintf("file-%d", i)})
		}

		env := map[string]any{"object": "list", "data": data}
		if s.sendTotal {
			env["total"] = s.total
		}
		if s.sendHasMore {
			env["has_more"] = start+len(data) < s.total
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(env))
	}
}

func newTestClient(t *testing.T, h http.Handler) *Client {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient("test-token", WithBaseURL(srv.URL))
}

func TestListPaged(t *testing.T) {
	tests := []struct {
		name        string
		total       int
		perPage     int
		sendHasMore bool
		sendTotal   bool
		wantItems   int
		wantPages   int
	}{
		{
			name:  "has_more drives multi-page collection",
			total: 230, perPage: defaultPageSize,
			sendHasMore: true, sendTotal: false,
			wantItems: 230, wantPages: 3,
		},
		{
			name:  "total drives multi-page collection when has_more absent",
			total: 230, perPage: defaultPageSize,
			sendTotal: true,
			wantItems: 230, wantPages: 3,
		},
		{
			name:  "short page terminates when no metadata present",
			total: 40, perPage: defaultPageSize,
			wantItems: 40, wantPages: 1,
		},
		{
			name:  "full page then empty page terminates without metadata",
			total: defaultPageSize, perPage: defaultPageSize,
			wantItems: defaultPageSize, wantPages: 2,
		},
		{
			// A server that caps page_size below the request must NOT be cut
			// short by the short-page heuristic while total is authoritative.
			name:  "server-side page_size cap does not truncate when total is present",
			total: 120, perPage: 50,
			sendTotal: true,
			wantItems: 120, wantPages: 3,
		},
		{
			name:  "empty result set",
			total: 0, perPage: defaultPageSize,
			sendTotal: true,
			wantItems: 0, wantPages: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &pagedServer{
				total: tc.total, perPage: tc.perPage,
				sendHasMore: tc.sendHasMore, sendTotal: tc.sendTotal,
			}
			c := newTestClient(t, srv.handler(t))

			files, err := c.ListFiles(context.Background())
			require.NoError(t, err)
			assert.Len(t, files, tc.wantItems)
			assert.Equal(t, tc.wantPages, srv.requests, "page request count")

			// IDs must be contiguous and de-duplicated across pages.
			for i, f := range files {
				assert.Equal(t, fmt.Sprintf("file-%d", i), f.ID)
			}
		})
	}
}

func TestListPaged_ErrorPropagates(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"boom"}`))
	}))

	_, err := c.ListFiles(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestRequest_DetailStyleErrorSurfaces(t *testing.T) {
	// A 422 validation error uses "detail", not "message". The old code left
	// the surfaced error empty; it must now carry the detail payload.
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":"page_size too large"}`))
	}))

	_, err := c.ListModels(context.Background())
	require.Error(t, err)
	assert.Equal(t, "page_size too large", err.Error())

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode)
}

func TestRequest_NonJSONErrorBody(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream unavailable"))
	}))

	_, err := c.ListModels(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
	assert.Contains(t, err.Error(), "upstream unavailable")
}

func TestAPIErrorError(t *testing.T) {
	tests := []struct {
		name string
		err  APIError
		want string
	}{
		{"message wins", APIError{Message: "nope", StatusCode: 400}, "nope"},
		{"detail string", APIError{Detail: json.RawMessage(`"bad field"`), StatusCode: 422}, "bad field"},
		{"detail array raw", APIError{Detail: json.RawMessage(`[{"msg":"x"}]`), StatusCode: 422}, `[{"msg":"x"}]`},
		{"status fallback", APIError{StatusCode: 500}, "mistral API error (status 500)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.err.Error())
		})
	}
}

func TestIsAccessDenied(t *testing.T) {
	assert.True(t, IsAccessDenied(&APIError{StatusCode: 401}))
	assert.True(t, IsAccessDenied(&APIError{StatusCode: 403}))
	assert.False(t, IsAccessDenied(&APIError{StatusCode: 500}))
	assert.False(t, IsAccessDenied(fmt.Errorf("plain error")))
	assert.False(t, IsAccessDenied(nil))
}

// cursorServer serves Connector objects one page at a time, keyed by an opaque
// cursor. stuck makes it hand back the cursor it was given, which a walk with
// no repeat guard would follow forever; after failAfter requests it returns a
// 500 so such a walk fails fast rather than hanging the suite.
type cursorServer struct {
	total     int
	perPage   int
	stuck     bool
	failAfter int
	requests  int
	cursors   []string // cursor received on each request, "" on the first
}

func (s *cursorServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.requests++
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		cursor := r.URL.Query().Get("cursor")
		s.cursors = append(s.cursors, cursor)

		if s.failAfter > 0 && s.requests > s.failAfter {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"walk did not terminate"}`))
			return
		}

		start := 0
		if cursor != "" && !s.stuck {
			var err error
			start, err = strconv.Atoi(cursor)
			require.NoError(t, err)
		}

		items := []Connector{}
		for i := start; i < start+s.perPage && i < s.total; i++ {
			items = append(items, Connector{ID: fmt.Sprintf("conn-%d", i)})
		}

		env := map[string]any{"items": items}
		next := start + len(items)
		switch {
		case s.stuck:
			env["pagination"] = map[string]any{"page_size": s.perPage, "next_cursor": "same-cursor-every-time"}
		case next < s.total:
			env["pagination"] = map[string]any{"page_size": s.perPage, "next_cursor": strconv.Itoa(next)}
		default:
			env["pagination"] = map[string]any{"page_size": s.perPage, "next_cursor": nil}
		}

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(env))
	}
}

func TestListConnectors_FollowsCursorToTheEnd(t *testing.T) {
	srv := &cursorServer{total: 7, perPage: 3}
	c := newTestClient(t, srv.handler(t))

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err)

	require.Len(t, connectors, 7, "every page must be collected")
	for i, conn := range connectors {
		assert.Equal(t, fmt.Sprintf("conn-%d", i), conn.ID)
	}
	assert.Equal(t, 3, srv.requests)
	// The cursor the server handed back must be the one sent on the next
	// request; dropping it re-reads page one instead of advancing.
	assert.Equal(t, []string{"", "3", "6"}, srv.cursors)
}

func TestListConnectors_SinglePageStopsAtNullCursor(t *testing.T) {
	srv := &cursorServer{total: 2, perPage: 100}
	c := newTestClient(t, srv.handler(t))

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err)
	assert.Len(t, connectors, 2)
	assert.Equal(t, 1, srv.requests, "a null next_cursor ends the walk")
}

func TestListConnectors_RepeatedCursorTerminates(t *testing.T) {
	srv := &cursorServer{total: 50, perPage: 2, stuck: true, failAfter: 6}
	c := newTestClient(t, srv.handler(t))

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err, "the walk must stop on a repeated cursor")
	assert.Len(t, connectors, 4, "the two pages read before the repeat are kept")
	assert.Equal(t, 2, srv.requests)
}

// connectorPayload is one connector as the API reports it, including the
// credential-shaped material the provider must not decode.
const connectorPayload = `{
  "items": [
    {
      "id": "0199a1b2-c3d4-7e8f-9012-3456789abcde",
      "name": "internal_tickets",
      "title": "Internal Tickets",
      "description": "Reads the ticket tracker",
      "server": "https://mcp.example.invalid/mcp",
      "protocol": "mcp",
      "visibility": "shared_org",
      "owner_type": "workspace",
      "owner_id": "11111111-2222-3333-4444-555555555555",
      "private_tool_execution": true,
      "created_at": "2026-03-04T05:06:07Z",
      "modified_at": "2026-04-05T06:07:08Z",
      "supported_auth_methods": [
        {
          "method_type": "bearer",
          "has_default_credentials": true,
          "headers": [{"name": "Authorization", "is_required": true, "is_secret": true}],
          "global_headers": {
            "Authorization": {"is_secret": true, "value": "header-value-must-not-be-decoded"}
          }
        },
        {"method_type": "oauth2", "has_default_credentials": false}
      ],
      "connection_credentials": [
        {"name": "default", "authentication_type": "bearer", "scope": "workspace"}
      ]
    }
  ],
  "pagination": {"page_size": 100, "next_cursor": null}
}`

func staticJSONClient(t *testing.T, body string) *Client {
	return newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestListConnectors_DecodesEveryModeledField(t *testing.T) {
	c := staticJSONClient(t, connectorPayload)

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err)
	require.Len(t, connectors, 1)
	got := connectors[0]

	assert.Equal(t, "0199a1b2-c3d4-7e8f-9012-3456789abcde", got.ID)
	assert.Equal(t, "internal_tickets", got.Name)
	assert.Equal(t, "Reads the ticket tracker", got.Description)
	require.NotNil(t, got.Server)
	assert.Equal(t, "https://mcp.example.invalid/mcp", *got.Server)
	assert.Equal(t, "mcp", got.Protocol)
	// A mistyped visibility tag reads empty here, which is how a shared_org
	// connector would silently stop matching a policy.
	assert.Equal(t, "shared_org", got.Visibility)
	assert.Equal(t, "workspace", got.OwnerType)
	assert.True(t, got.PrivateToolExecution)
	assert.Equal(t, []string{"bearer", "oauth2"}, got.AuthMethodNames())

	require.NotNil(t, got.CreatedAt)
	assert.Equal(t, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), got.CreatedAt.UTC())
	require.NotNil(t, got.ModifiedAt)
	assert.Equal(t, time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC), got.ModifiedAt.UTC())
}

func TestListConnectors_DoesNotDecodeAuthMaterial(t *testing.T) {
	c := staticJSONClient(t, connectorPayload)

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err)
	require.Len(t, connectors, 1)

	// Re-encoding the decoded struct shows everything the provider retained.
	// Adding a headers or connection_credentials field to Connector or to
	// ConnectorAuthMethod fails this.
	encoded, err := json.Marshal(connectors[0])
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "header-value-must-not-be-decoded")
	assert.NotContains(t, string(encoded), "global_headers")
	assert.NotContains(t, string(encoded), "connection_credentials")
	assert.Contains(t, string(encoded), "bearer", "the method name itself is kept")
}

func TestListConnectors_MissingOptionalFieldsAreNull(t *testing.T) {
	c := staticJSONClient(t, `{"items":[{"id":"c1","name":"n","description":"","owner_type":"user",`+
		`"visibility":"private","private_tool_execution":false,"server":null,"supported_auth_methods":null}],`+
		`"pagination":{"page_size":100}}`)

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err)
	require.Len(t, connectors, 1)

	assert.Nil(t, connectors[0].Server, "an absent server URL stays null")
	assert.Nil(t, connectors[0].CreatedAt, "an absent timestamp stays null, not year 1")
	assert.Empty(t, connectors[0].AuthMethodNames())
}

func TestAuthMethodNames_SkipsUnnamedMethods(t *testing.T) {
	c := Connector{SupportedAuthMethods: []ConnectorAuthMethod{
		{MethodType: "oauth2"}, {MethodType: ""}, {MethodType: "none"},
	}}
	assert.Equal(t, []string{"oauth2", "none"}, c.AuthMethodNames())
}

// tokenServer serves objects carrying only an id, paged by an opaque
// continuation token. Ids are "<prefix>-<n>", prefix defaulting to "lib".
type tokenServer struct {
	total     int
	perPage   int
	stuck     bool
	failAfter int
	prefix    string
	requests  int
	tokens    []string
	paths     []string
}

func (s *tokenServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.requests++
		token := r.URL.Query().Get("page_token")
		s.tokens = append(s.tokens, token)
		s.paths = append(s.paths, r.URL.Path)

		if s.failAfter > 0 && s.requests > s.failAfter {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"walk did not terminate"}`))
			return
		}

		start := 0
		if token != "" && !s.stuck {
			var err error
			start, err = strconv.Atoi(token)
			require.NoError(t, err)
		}

		prefix := s.prefix
		if prefix == "" {
			prefix = "lib"
		}
		data := []map[string]any{}
		for i := start; i < start+s.perPage && i < s.total; i++ {
			data = append(data, map[string]any{"id": fmt.Sprintf("%s-%d", prefix, i)})
		}

		env := map[string]any{"data": data}
		next := start + len(data)
		switch {
		case s.stuck:
			env["next_page_token"] = "same-token-every-time"
		case next < s.total:
			env["next_page_token"] = strconv.Itoa(next)
		default:
			env["next_page_token"] = nil
		}

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(env))
	}
}

func TestListLibraries_FollowsPageToken(t *testing.T) {
	srv := &tokenServer{total: 5, perPage: 2}
	c := newTestClient(t, srv.handler(t))

	libraries, err := c.ListLibraries(context.Background())
	require.NoError(t, err)

	require.Len(t, libraries, 5)
	for i, l := range libraries {
		assert.Equal(t, fmt.Sprintf("lib-%d", i), l.ID)
	}
	assert.Equal(t, 3, srv.requests)
	assert.Equal(t, []string{"", "2", "4"}, srv.tokens)
}

func TestListLibraries_RepeatedTokenTerminates(t *testing.T) {
	srv := &tokenServer{total: 50, perPage: 2, stuck: true, failAfter: 6}
	c := newTestClient(t, srv.handler(t))

	libraries, err := c.ListLibraries(context.Background())
	require.NoError(t, err, "the walk must stop on a repeated page token")
	assert.Len(t, libraries, 4)
	assert.Equal(t, 2, srv.requests)
}

func TestListLibraries_DecodesEveryModeledField(t *testing.T) {
	c := staticJSONClient(t, `{"data":[{
		"id":"0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
		"name":"Company handbook",
		"description":"Onboarding material",
		"created_at":"2026-01-02T03:04:05Z",
		"updated_at":"2026-02-03T04:05:06Z",
		"owner_id":"99999999-8888-7777-6666-555555555555",
		"owner_type":"Workspace",
		"total_size":1048576,
		"nb_documents":42,
		"chunk_size":null
	}],"next_page_token":null}`)

	libraries, err := c.ListLibraries(context.Background())
	require.NoError(t, err)
	require.Len(t, libraries, 1)
	got := libraries[0]

	assert.Equal(t, "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee", got.ID)
	assert.Equal(t, "Company handbook", got.Name)
	require.NotNil(t, got.Description)
	assert.Equal(t, "Onboarding material", *got.Description)
	assert.Equal(t, "Workspace", got.OwnerType)
	require.NotNil(t, got.OwnerID)
	assert.Equal(t, "99999999-8888-7777-6666-555555555555", *got.OwnerID)
	// nb_documents and total_size are what a corpus-size policy reads; swapped
	// or mistyped tags read zero on a library that holds documents.
	assert.Equal(t, int64(42), got.NbDocuments)
	assert.Equal(t, int64(1048576), got.TotalSize)
	require.NotNil(t, got.CreatedAt)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), got.CreatedAt.UTC())
	require.NotNil(t, got.UpdatedAt)
	assert.Equal(t, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC), got.UpdatedAt.UTC())
}

func TestListLibraries_MissingOptionalFieldsAreNull(t *testing.T) {
	c := staticJSONClient(t, `{"data":[{"id":"l1","name":"n","owner_type":"User",`+
		`"owner_id":null,"description":null,"total_size":0,"nb_documents":0}]}`)

	libraries, err := c.ListLibraries(context.Background())
	require.NoError(t, err)
	require.Len(t, libraries, 1)

	assert.Nil(t, libraries[0].Description)
	assert.Nil(t, libraries[0].OwnerID)
	assert.Nil(t, libraries[0].CreatedAt, "an absent timestamp stays null, not year 1")
}

func TestListLibraryAccesses(t *testing.T) {
	var gotPath string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"library_id":"lib-1","org_id":"org-1","role":"Editor","share_with_type":"User",
			 "share_with_uuid":"11111111-1111-1111-1111-111111111111"},
			{"library_id":"lib-1","org_id":"org-1","role":"Viewer","share_with_type":"Org",
			 "share_with_uuid":null}
		]}`))
	}))

	accesses, err := c.ListLibraryAccesses(context.Background(), "lib/1")
	require.NoError(t, err)
	assert.Equal(t, "/v1/libraries/lib%2F1/share", gotPath, "the library id is path-escaped")

	require.Len(t, accesses, 2)
	assert.Equal(t, "Editor", accesses[0].Role)
	assert.Equal(t, "User", accesses[0].ShareWithType)
	require.NotNil(t, accesses[0].ShareWithUUID)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", *accesses[0].ShareWithUUID)

	assert.Equal(t, "Org", accesses[1].ShareWithType)
	assert.Equal(t, "Viewer", accesses[1].Role)
	assert.Nil(t, accesses[1].ShareWithUUID, "an org-wide share names no single entity")
}

func TestListBatchJobs_DecodesErrorsAndMetadata(t *testing.T) {
	c := staticJSONClient(t, `{"object":"list","has_more":false,"data":[{
		"id":"batch-1","status":"FAILED","endpoint":"/v1/chat/completions",
		"total_requests":10,"failed_requests":4,
		"errors":[{"message":"rate limit exceeded","count":3},{"message":"content filtered"}],
		"metadata":{"team":"platform","ticket":"OPS-1"}
	}]}`)

	jobs, err := c.ListBatchJobs(context.Background())
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	require.Len(t, jobs[0].Errors, 2)
	assert.Equal(t, "rate limit exceeded", jobs[0].Errors[0].Message)
	assert.Equal(t, 3, jobs[0].Errors[0].Count)
	assert.Equal(t, "content filtered", jobs[0].Errors[1].Message)
	assert.Equal(t, map[string]string{"team": "platform", "ticket": "OPS-1"}, jobs[0].Metadata)
}

func TestListFineTuningJobs_DecodesIntegrations(t *testing.T) {
	c := staticJSONClient(t, `{"object":"list","has_more":false,"data":[{
		"id":"ft-1","status":"SUCCESS","model":"open-mistral-7b",
		"integrations":[
			{"type":"wandb","project":"finetunes","name":"tracker","run_name":"run-7",
			 "url":"https://wandb.example.invalid/finetunes/run-7"},
			{"type":"wandb","project":"finetunes","run_name":null,"url":null}
		]
	}]}`)

	jobs, err := c.ListFineTuningJobs(context.Background())
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.Len(t, jobs[0].Integrations, 2)

	first := jobs[0].Integrations[0]
	assert.Equal(t, "wandb", first.Type)
	assert.Equal(t, "finetunes", first.Project)
	require.NotNil(t, first.RunName)
	assert.Equal(t, "run-7", *first.RunName)
	require.NotNil(t, first.URL)
	assert.Equal(t, "https://wandb.example.invalid/finetunes/run-7", *first.URL)

	assert.Nil(t, jobs[0].Integrations[1].RunName, "an absent run name stays null")
	assert.Nil(t, jobs[0].Integrations[1].URL)
}

func TestListConnectors_AccessDeniedIsClassified(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"not permitted"}`))
	}))

	_, err := c.ListConnectors(context.Background())
	require.Error(t, err)
	assert.True(t, IsAccessDenied(err), "a 403 on connectors must read as not permitted")
}

// Synthetic: three-page token walk; no live account was checked.
func TestListAgents_FollowsPageToken(t *testing.T) {
	srv := &tokenServer{total: 5, perPage: 2, prefix: "ag"}
	c := newTestClient(t, srv.handler(t))

	agents, err := c.ListAgents(context.Background())
	require.NoError(t, err)

	require.Len(t, agents, 5)
	for i, a := range agents {
		assert.Equal(t, fmt.Sprintf("ag-%d", i), a.ID)
	}
	assert.Equal(t, []string{"", "2", "4"}, srv.tokens)
	// The offset-paginated /v1/agents listing is deprecated; the walk must use
	// the token-paginated one.
	assert.Equal(t, []string{"/v1/agents/pages", "/v1/agents/pages", "/v1/agents/pages"}, srv.paths)
}

// Synthetic: server that hands back the same token forever; no live account was checked.
func TestListAgents_RepeatedTokenTerminates(t *testing.T) {
	srv := &tokenServer{total: 50, perPage: 2, stuck: true, failAfter: 6, prefix: "ag"}
	c := newTestClient(t, srv.handler(t))

	agents, err := c.ListAgents(context.Background())
	require.NoError(t, err, "the walk must stop on a repeated page token")
	assert.Len(t, agents, 4)
	assert.Equal(t, 2, srv.requests)
}

// Synthetic: payload shaped after the Agent schema in the public OpenAPI spec; no live account was checked.
const agentPayload = `{
  "object": "list",
  "data": [
    {
      "id": "ag_0001",
      "object": "agent",
      "name": "support-triage",
      "description": "Routes tickets",
      "version": 3,
      "versions": [1, 2, 3],
      "model": "mistral-medium-latest",
      "instructions": "Be brief.",
      "deployment_chat": false,
      "source": "api",
      "tools": [
        {"type": "function", "function": {"name": "lookup_ticket", "parameters": {"type": "object"}}},
        {"type": "document_library", "library_ids": ["lib-a", "lib-b"]},
        {"type": "connector", "connector_id": "conn-1",
         "authorization": {"type": "api-key", "value": "api-key-must-not-be-decoded"},
         "tool_configuration": {"requires_confirmation": ["create_issue"], "include": ["create_issue", "search"], "exclude": ["delete_repo"]}},
        {"type": "document_library", "library_ids": ["lib-b"]},
        {"type": "web_search"}
      ],
      "guardrails": [{"block_on_error": true}, {"block_on_error": true}],
      "handoffs": ["ag_0002"],
      "created_at": "2026-03-04T05:06:07Z",
      "updated_at": "2026-04-05T06:07:08Z"
    }
  ],
  "next_page_token": null
}`

func TestListAgents_DecodesEveryModeledField(t *testing.T) {
	c := staticJSONClient(t, agentPayload)

	agents, err := c.ListAgents(context.Background())
	require.NoError(t, err)
	require.Len(t, agents, 1)
	got := agents[0]

	assert.Equal(t, "ag_0001", got.ID)
	assert.Equal(t, "support-triage", got.Name)
	require.NotNil(t, got.Description)
	assert.Equal(t, "Routes tickets", *got.Description)
	assert.Equal(t, int64(3), got.Version)
	assert.Equal(t, "mistral-medium-latest", got.Model)
	require.NotNil(t, got.Instructions)
	assert.Equal(t, "Be brief.", *got.Instructions)
	assert.Equal(t, []string{"ag_0002"}, got.Handoffs)

	require.Len(t, got.Tools, 5)
	assert.Equal(t, "function", got.Tools[0].Type)
	require.NotNil(t, got.Tools[0].Function)
	assert.Equal(t, "lookup_ticket", got.Tools[0].Function.Name)
	assert.Equal(t, []string{"lib-a", "lib-b"}, got.Tools[1].LibraryIDs)
	require.NotNil(t, got.Tools[2].ConnectorID)
	assert.Equal(t, "conn-1", *got.Tools[2].ConnectorID)
	require.NotNil(t, got.Tools[2].ToolConfiguration)
	assert.Equal(t, []string{"create_issue"}, got.Tools[2].ToolConfiguration.RequiresConfirmation)
	assert.Equal(t, []string{"create_issue", "search"}, got.Tools[2].ToolConfiguration.Include)
	assert.Equal(t, []string{"delete_repo"}, got.Tools[2].ToolConfiguration.Exclude)
	assert.Nil(t, got.Tools[4].ToolConfiguration)

	assert.Equal(t, []string{"lib-a", "lib-b"}, got.LibraryIDs(), "a library two tools search is listed once")
	assert.Equal(t, []string{"conn-1"}, got.ConnectorIDs())
	require.NotNil(t, got.GuardrailsBlockOnError())
	assert.True(t, *got.GuardrailsBlockOnError())

	require.NotNil(t, got.CreatedAt)
	assert.Equal(t, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), got.CreatedAt.UTC())
	require.NotNil(t, got.UpdatedAt)
	assert.Equal(t, time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC), got.UpdatedAt.UTC())

	// Re-encoding shows everything the provider retained. Decoding a
	// connector tool's authorization block fails this.
	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "api-key-must-not-be-decoded")
}

// Synthetic: minimal agent with every optional field absent; no live account was checked.
func TestListAgents_MissingOptionalFieldsAreNull(t *testing.T) {
	c := staticJSONClient(t, `{"data":[{"id":"ag","name":"n","model":"m","version":0}]}`)

	agents, err := c.ListAgents(context.Background())
	require.NoError(t, err)
	require.Len(t, agents, 1)

	assert.Nil(t, agents[0].Description)
	assert.Nil(t, agents[0].Instructions)
	assert.Nil(t, agents[0].CreatedAt, "an absent timestamp stays null, not year 1")
	assert.Nil(t, agents[0].GuardrailsBlockOnError(), "no guardrails is null, not false")
	assert.Empty(t, agents[0].LibraryIDs())
	assert.Empty(t, agents[0].ConnectorIDs())
}

// Synthetic: payload shaped after the Webhook schema in the public OpenAPI spec; no live account was checked.
const webhookJSON = `{
  "id": "5f0c6d1e-0000-4000-8000-000000000001",
  "creator_id": "5f0c6d1e-0000-4000-8000-0000000000aa",
  "organization_id": "5f0c6d1e-0000-4000-8000-0000000000bb",
  "workspace_id": "5f0c6d1e-0000-4000-8000-0000000000cc",
  "owner_type": "workspace",
  "provider": "github",
  "name": "repo-events",
  "url": "https://hooks.example.invalid/in/abc",
  "http_method": "POST",
  "url_verified": true,
  "url_verification_token": "verification-token-must-not-be-decoded",
  "signature_hash_algorithm": "sha256",
  "signature_header_name": "X-Hub-Signature-256",
  "validity_period_second": 300,
  "signature_extractor_regex": null,
  "timestamp_extractor_regex": null,
  "signature_payload_pattern": null,
  "signature_encoding": "hex",
  "success_status_code": 200,
  "expires_at": "2027-01-02T03:04:05Z",
  "created_at": "2026-03-04T05:06:07Z",
  "updated_at": "2026-04-05T06:07:08Z"
}`

func TestListWebhooks_DecodesEveryModeledField(t *testing.T) {
	var gotPath string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[" + webhookJSON + "]"))
	}))

	webhooks, err := c.ListWebhooks(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "/v1/webhooks", gotPath)
	require.Len(t, webhooks, 1)
	got := webhooks[0]

	assert.Equal(t, "5f0c6d1e-0000-4000-8000-000000000001", got.ID)
	assert.Equal(t, "repo-events", got.Name)
	assert.Equal(t, "github", got.Provider)
	assert.Equal(t, "https://hooks.example.invalid/in/abc", got.URL)
	require.NotNil(t, got.URLVerified)
	assert.True(t, *got.URLVerified)
	require.NotNil(t, got.SignatureHashAlgorithm)
	assert.Equal(t, "sha256", *got.SignatureHashAlgorithm)
	require.NotNil(t, got.ValidityPeriodSecond)
	assert.Equal(t, int64(300), *got.ValidityPeriodSecond)
	assert.Equal(t, "workspace", got.OwnerType)
	require.NotNil(t, got.ExpiresAt)
	assert.Equal(t, time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), got.ExpiresAt.UTC())
	require.NotNil(t, got.CreatedAt)
	require.NotNil(t, got.UpdatedAt)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "verification-token-must-not-be-decoded")
}

// Synthetic: unsigned, unverified, non-expiring webhook; no live account was checked.
func TestListWebhooks_MissingOptionalFieldsAreNull(t *testing.T) {
	c := staticJSONClient(t, `[{"id":"w","name":"n","provider":"custom","url":"u","owner_type":"user",`+
		`"url_verified":null,"signature_hash_algorithm":null,"validity_period_second":null,"expires_at":null}]`)

	webhooks, err := c.ListWebhooks(context.Background())
	require.NoError(t, err)
	require.Len(t, webhooks, 1)
	assert.Nil(t, webhooks[0].URLVerified, "an unverified-by-design URL is null, not false")
	assert.Nil(t, webhooks[0].SignatureHashAlgorithm)
	assert.Nil(t, webhooks[0].ValidityPeriodSecond, "no validity period is null, not 0")
	assert.Nil(t, webhooks[0].ExpiresAt)
}

// Synthetic: 401 on the webhook listing; no live account was checked.
func TestListWebhooks_AccessDeniedIsClassified(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"no"}`))
	}))

	_, err := c.ListWebhooks(context.Background())
	require.Error(t, err)
	assert.True(t, IsAccessDenied(err))
}

// Synthetic: payload shaped after the Trigger schema in the public OpenAPI spec; no live account was checked.
func TestListTriggers_DecodesEveryModeledField(t *testing.T) {
	var gotPath string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
		  {"id":"t1","creator_id":"u","workspace_id":"w","organization_id":"o","customer_id":"c",
		   "owner_type":"user","event_source":` + webhookJSON + `,"handler":"agents",
		   "action":{"primitive_id":"ag_0001","type":"start_agent_session"},
		   "filters":"event.type == 'push'","title":"On push"},
		  {"id":"t2","owner_type":"workspace","event_source":` + webhookJSON + `,"handler":"workflows",
		   "action":{"primitive_id":"wf-9","type":"start_workflow"},"filters":null,"title":"Nightly"}
		]`))
	}))

	triggers, err := c.ListTriggers(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "/v1/triggers", gotPath)
	require.Len(t, triggers, 2)

	got := triggers[0]
	assert.Equal(t, "t1", got.ID)
	assert.Equal(t, "On push", got.Title)
	assert.Equal(t, "user", got.OwnerType)
	assert.Equal(t, "agents", got.Handler)
	assert.Equal(t, "ag_0001", got.Action.PrimitiveID)
	assert.Equal(t, TriggerActionStartAgentSession, got.Action.Type)
	require.NotNil(t, got.Filters)
	assert.Equal(t, "event.type == 'push'", *got.Filters)
	require.NotNil(t, got.EventSource)
	assert.Equal(t, "5f0c6d1e-0000-4000-8000-000000000001", got.EventSource.ID)
	assert.Equal(t, "github", got.EventSource.Provider)

	assert.Nil(t, triggers[1].Filters, "no filter is null, not an empty expression")
	assert.Equal(t, "start_workflow", triggers[1].Action.Type)
}

// Synthetic: connector payload carrying the ownership, credential-state and blocking fields; no live account was checked.
func TestListConnectors_DecodesOwnershipAndBlocking(t *testing.T) {
	c := staticJSONClient(t, `{"items":[{"id":"c1","name":"jira","title":"Jira","description":"",
		"owner_type":"workspace","owner_id":"ws-1","creator_id":"user-1","visibility":"shared_workspace",
		"private_tool_execution":false,"protocol":"http","is_authenticated":false,"blocked_by":["org","user"],
		"connection_preferences":[
		  {"consumer_type":"org","http_proxy_enabled":true,"tool_configuration":{}},
		  {"consumer_type":"workspace","http_proxy_enabled":false,"tool_configuration":{}}
		]}],"pagination":{"page_size":100}}`)

	connectors, err := c.ListConnectors(context.Background())
	require.NoError(t, err)
	require.Len(t, connectors, 1)
	got := connectors[0]

	require.NotNil(t, got.Title)
	assert.Equal(t, "Jira", *got.Title)
	require.NotNil(t, got.OwnerID)
	assert.Equal(t, "ws-1", *got.OwnerID)
	require.NotNil(t, got.CreatorID)
	assert.Equal(t, "user-1", *got.CreatorID)
	assert.Equal(t, []string{"org", "user"}, got.BlockedBy)
	require.Len(t, got.ConnectionPreferences, 2)
	require.NotNil(t, got.HTTPProxyEnabled())
	assert.False(t, *got.HTTPProxyEnabled(), "a workspace-level false switches raw HTTP off")
}

// Synthetic: file record carrying visibility and expiry; no live account was checked.
func TestListFiles_DecodesVisibilityAndExpiry(t *testing.T) {
	c := staticJSONClient(t, `{"object":"list","total":2,"data":[
		{"id":"f1","object":"file","bytes":1,"created_at":1,"filename":"a.jsonl","purpose":"batch",
		 "sample_type":"batch_request","source":"upload","visibility":"user","expires_at":1767225600},
		{"id":"f2","object":"file","bytes":1,"created_at":1,"filename":"b.jsonl","purpose":"batch",
		 "sample_type":"batch_request","source":"upload"}]}`)

	files, err := c.ListFiles(context.Background())
	require.NoError(t, err)
	require.Len(t, files, 2)
	require.NotNil(t, files[0].Visibility)
	assert.Equal(t, "user", *files[0].Visibility)
	require.NotNil(t, files[0].ExpiresAt)
	assert.Equal(t, int64(1767225600), *files[0].ExpiresAt)
	assert.Nil(t, files[1].Visibility)
	assert.Nil(t, files[1].ExpiresAt, "a file that does not expire has no expiry")
}

// Synthetic: batch run through an agent rather than a model; no live account was checked.
func TestListBatchJobs_DecodesAgentID(t *testing.T) {
	c := staticJSONClient(t, `{"object":"list","total":1,"data":[{"id":"b1","input_files":["f1"],
		"endpoint":"/v1/agents/completions","model":null,"agent_id":"ag_0001","errors":[],"status":"SUCCESS",
		"created_at":1,"total_requests":1,"completed_requests":1,"succeeded_requests":1,"failed_requests":0}]}`)

	jobs, err := c.ListBatchJobs(context.Background())
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.NotNil(t, jobs[0].AgentID)
	assert.Equal(t, "ag_0001", *jobs[0].AgentID)
	assert.Nil(t, jobs[0].Model)
}
