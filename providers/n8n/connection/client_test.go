// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// The fixtures in testdata are responses from a local n8n 2.44.6
// (docker.n8n.io/n8nio/n8n:2.44.6, community edition, unlicensed), captured
// 2026-10-25 with curl against the Public API. workflows-active.json was
// captured after seeding: the webhook workflow published, the HTTP workflow
// with an error workflow and Europe/Berlin timezone. The other files were
// captured after the webhook workflow was deactivated and archived, the HTTP
// workflow's settings were changed, and a community package was installed.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

// fixtureServer serves each path from the given fixture with a status code.
type served struct {
	status int
	file   string
}

func fixtureServer(t *testing.T, routes map[string]served) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(route.status)
		_, _ = w.Write(fixture(t, route.file))
	}))
	t.Cleanup(srv.Close)
	return testClient(t, srv.URL)
}

func testClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	return &Client{baseURL: serverURL, apiKey: "test-key", http: http.DefaultClient}
}

func TestWorkflows(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25, after the state change.
	c := fixtureServer(t, map[string]served{"/api/v1/workflows": {200, "workflows.json"}})
	workflows, err := c.Workflows(context.Background())
	require.NoError(t, err)
	require.Len(t, workflows, 2)

	webhook := workflows[0]
	assert.Equal(t, "rgNSSvk5U0wgznVg", webhook.ID)
	assert.Equal(t, "mql-verify-open-webhook", webhook.Name)
	assert.False(t, webhook.Active())
	assert.True(t, webhook.IsArchived)
	assert.Equal(t, int64(1), webhook.TriggerCount)
	assert.Equal(t, []string{"ll2ljqkTva8mmlWT"}, webhook.TagIDs)
	assert.Equal(t, "any", webhook.Settings.CallerPolicy)
	assert.Equal(t, "all", webhook.Settings.SaveDataErrorExecution)
	assert.Empty(t, webhook.Settings.SaveDataSuccessExecution)
	assert.Nil(t, webhook.Settings.ExecutionTimeout)
	assert.Nil(t, webhook.Settings.AvailableInMCP)
	require.Len(t, webhook.Nodes, 1)
	hook := webhook.Nodes[0]
	assert.Equal(t, "n8n-nodes-base.webhook", hook.Type)
	assert.Equal(t, "9f1b6b4e-1a2b-4c3d-8e9f-0a1b2c3d4e5f", hook.WebhookID)
	assert.Equal(t, "none", hook.Authentication)
	assert.Empty(t, hook.CredentialIDs)

	httpWf := workflows[1]
	assert.Equal(t, "mql-verify-http", httpWf.Name)
	assert.False(t, httpWf.IsArchived)
	assert.Equal(t, "workflowsFromAList", httpWf.Settings.CallerPolicy)
	assert.Equal(t, []string{"abc123", "rgNSSvk5U0wgznVg"}, httpWf.Settings.CallerIDs)
	assert.Equal(t, "rgNSSvk5U0wgznVg", httpWf.Settings.ErrorWorkflowID)
	assert.Equal(t, "UTC", httpWf.Settings.Timezone)
	assert.Equal(t, "none", httpWf.Settings.SaveDataSuccessExecution)
	require.NotNil(t, httpWf.Settings.ExecutionTimeout)
	assert.Equal(t, int64(300), *httpWf.Settings.ExecutionTimeout)
	require.Len(t, httpWf.Nodes, 3)
	request := httpWf.Nodes[1]
	assert.Equal(t, "HTTP Request", request.Name)
	// Decoding through a float32 turns this into 4.199999809265137.
	assert.Equal(t, 4.2, request.TypeVersion)
	assert.True(t, request.RetryOnFail)
	assert.Equal(t, "continueRegularOutput", request.OnError)
	assert.Equal(t, []string{"Y2ILtunxAFKvFQyE"}, request.CredentialIDs)
	assert.True(t, httpWf.Nodes[2].Disabled)
}

func TestWorkflowsActive(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25, before the state change. `active` is
	// deprecated upstream; activeVersionId is what says the workflow runs.
	c := fixtureServer(t, map[string]served{"/api/v1/workflows": {200, "workflows-active.json"}})
	workflows, err := c.Workflows(context.Background())
	require.NoError(t, err)
	require.Len(t, workflows, 2)
	assert.True(t, workflows[0].Active())
	assert.Equal(t, "c005f2ed-22ed-41b1-bbb6-8002ef020e3c", workflows[0].ActiveVersionID)
	assert.False(t, workflows[0].IsArchived)
	assert.False(t, workflows[1].Active())
	assert.Equal(t, "Europe/Berlin", workflows[1].Settings.Timezone)
}

func TestWorkflowsPagination(t *testing.T) {
	// Synthetic: a two-page walk; the local instance never held more than a page.
	var cursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		cursors = append(cursors, cursor)
		assert.Equal(t, "250", r.URL.Query().Get("limit"))
		assert.Equal(t, "true", r.URL.Query().Get("excludePinnedData"))
		assert.Equal(t, "test-key", r.Header.Get("X-N8N-API-KEY"))
		w.Header().Set("Content-Type", "application/json")
		if cursor == "" {
			_, _ = w.Write([]byte(`{"data":[{"id":"a","name":"one","createdAt":"2026-10-26T00:37:11.195Z","updatedAt":"2026-10-26T00:37:11.195Z","nodes":[],"connections":{},"shared":[]}],"nextCursor":"page2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"b","name":"two","createdAt":"2026-10-26T00:37:11.195Z","updatedAt":"2026-10-26T00:37:11.195Z","nodes":[],"connections":{},"shared":[]}],"nextCursor":null}`))
	}))
	defer srv.Close()

	workflows, err := testClient(t, srv.URL).Workflows(context.Background())
	require.NoError(t, err)
	require.Len(t, workflows, 2)
	assert.Equal(t, "a", workflows[0].ID)
	assert.Equal(t, "b", workflows[1].ID)
	assert.Equal(t, []string{"", "page2"}, cursors)
}

func TestResponseSizeLimit(t *testing.T) {
	// Synthetic: a body past the cap is refused instead of read into memory.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := make([]byte, 1<<20)
		for i := range chunk {
			chunk[i] = ' '
		}
		for i := 0; i <= maxResponseBytes>>20; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	_, err := testClient(t, srv.URL).Tags(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response larger than 64 MB")
}

func TestWalkCursorRepeatedCursor(t *testing.T) {
	// Synthetic: an API that keeps returning the same cursor must not loop forever.
	calls := 0
	err := walkCursor(func(cursor *string) (*string, error) {
		calls++
		next := "same"
		return &next, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "twice")
	assert.Equal(t, 2, calls)
}

func TestWalkCursorStopsOnEmptyCursor(t *testing.T) {
	// Synthetic: an empty string cursor ends the walk like a null one.
	calls := 0
	err := walkCursor(func(cursor *string) (*string, error) {
		calls++
		empty := ""
		return &empty, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestCredentials(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25.
	c := fixtureServer(t, map[string]served{"/api/v1/credentials": {200, "credentials.json"}})
	creds, err := c.Credentials(context.Background())
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "CaLU2QV6Pt9NggSt", creds[0].ID)
	assert.Equal(t, "mql-verify-unused", creds[0].Name)
	assert.Equal(t, "httpHeaderAuth", creds[0].Type)
	assert.Equal(t, time.Date(2026, 10, 26, 0, 37, 10, 864000000, time.UTC), creds[0].CreatedAt.UTC())
}

func TestUsers(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25. The invited member has not set a name.
	c := fixtureServer(t, map[string]served{"/api/v1/users": {200, "users.json"}})
	users, err := c.Users(context.Background())
	require.NoError(t, err)
	require.Len(t, users, 2)

	member := users[0]
	assert.Equal(t, "member@example.com", member.Email)
	assert.Equal(t, "global:member", member.Role)
	assert.Empty(t, member.FirstName)
	require.NotNil(t, member.IsPending)
	assert.True(t, *member.IsPending)
	require.NotNil(t, member.MfaEnabled)
	assert.False(t, *member.MfaEnabled)

	owner := users[1]
	assert.Equal(t, "global:owner", owner.Role)
	assert.Equal(t, "Mql", owner.FirstName)
	require.NotNil(t, owner.IsPending)
	assert.False(t, *owner.IsPending)
}

func TestTags(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25.
	c := fixtureServer(t, map[string]served{"/api/v1/tags": {200, "tags.json"}})
	tags, err := c.Tags(context.Background())
	require.NoError(t, err)
	require.Len(t, tags, 1)
	assert.Equal(t, "ll2ljqkTva8mmlWT", tags[0].ID)
	assert.Equal(t, "mql-verify", tags[0].Name)
}

func TestCommunityPackages(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25, after installing
	// n8n-nodes-text-manipulation. It reports no author email and no update.
	c := fixtureServer(t, map[string]served{"/api/v1/community-packages": {200, "packages.json"}})
	pkgs, err := c.CommunityPackages(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	p := pkgs[0]
	assert.Equal(t, "n8n-nodes-text-manipulation", p.Name)
	assert.Equal(t, "1.4.0", p.InstalledVersion)
	assert.Equal(t, "lublak", p.AuthorName)
	assert.Empty(t, p.AuthorEmail)
	assert.Empty(t, p.UpdateAvailable)
	assert.False(t, p.FailedLoading)
	assert.Equal(t, []string{"n8n-nodes-text-manipulation.textManipulation"}, p.NodeTypes)
}

func TestAudit(t *testing.T) {
	// Measured: n8n 2.44.6, 2026-10-25. No database or filesystem risk was found,
	// so those reports are absent from the body.
	c := fixtureServer(t, map[string]served{"/api/v1/audit": {200, "audit.json"}})
	reports, err := c.Audit(context.Background())
	require.NoError(t, err)
	require.Len(t, reports, 3)
	assert.Equal(t, "credentials", reports[0].Risk)
	assert.Equal(t, "instance", reports[1].Risk)
	assert.Equal(t, "nodes", reports[2].Risk)

	unused := reports[0].Sections[0]
	assert.Equal(t, "Credentials not used in any workflow", unused.Title)
	require.Len(t, unused.Locations, 1)
	assert.Equal(t, map[string]any{"kind": "credential", "id": "CaLU2QV6Pt9NggSt", "name": "mql-verify-unused"}, unused.Locations[0])

	settings := reports[1].Sections[0]
	assert.Equal(t, "Security settings", settings.Title)
	assert.Empty(t, settings.Locations)
	features, ok := settings.Settings["features"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, features["communityPackagesEnabled"])

	require.Len(t, reports[2].Sections, 2)
	assert.Equal(t, "Community nodes", reports[2].Sections[1].Title)
	assert.Equal(t, "community", reports[2].Sections[1].Locations[0]["kind"])
}

func TestDecodeAuditEmpty(t *testing.T) {
	// Synthetic: the spec documents an empty array when no category finds a risk.
	reports, err := decodeAudit([]byte(`[]`))
	require.NoError(t, err)
	assert.Empty(t, reports)
	assert.NotNil(t, reports)
}

func TestDecodeAuditMalformed(t *testing.T) {
	// Synthetic: a body that is neither shape.
	_, err := decodeAudit([]byte(`"oops"`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrMalformedData))
}

func TestResponseErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		file   string
		kind   error
		perms  []string
		scoped bool
	}{
		// Measured: a revoked or wrong key, n8n 2.44.6, 2026-10-25.
		{name: "bad key", status: 401, file: "err-401.json", kind: llx.ErrUnauthenticated, scoped: true},
		// Measured: a key with only workflow:list and tag:list reading credentials.
		{name: "missing scope", status: 403, file: "err-403-scope.json", kind: llx.ErrForbidden, perms: []string{"credential:list"}},
		// Measured: GET /variables on an unlicensed instance.
		{name: "unlicensed feature", status: 403, file: "err-403-license.json", kind: llx.ErrNotApplicable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fixtureServer(t, map[string]served{"/api/v1/credentials": {tt.status, tt.file}})
			_, err := c.Credentials(context.Background())
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.kind), "got %v", err)
			var e *llx.Error
			require.True(t, errors.As(err, &e))
			assert.Equal(t, tt.perms, e.Permissions)
			assert.Equal(t, tt.scoped, e.Scope == llx.ErrorScope_ERROR_SCOPE_ASSET)
		})
	}
}

func TestResponseErrorStatuses(t *testing.T) {
	// Synthetic: statuses the local instance did not produce.
	resp := func(status int, header http.Header) *http.Response {
		return &http.Response{StatusCode: status, Header: header}
	}

	err := responseError(resp(429, http.Header{"Retry-After": []string{"30"}}), []byte(`{"message":"Too many requests"}`), "workflow:list")
	assert.True(t, errors.Is(err, llx.ErrTooManyRequests))
	var e *llx.Error
	require.True(t, errors.As(err, &e))
	assert.Equal(t, 30*time.Second, e.RetryAfter)

	assert.True(t, errors.Is(responseError(resp(502, nil), nil, ""), llx.ErrTargetUnavailable))

	// A 404 says nothing certain about why; it stays unclassified.
	err = responseError(resp(404, nil), []byte(`{"message":"not found"}`), "")
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	assert.Contains(t, err.Error(), "not found")

	assert.NoError(t, responseError(resp(200, nil), nil, ""))
}

func TestTransportError(t *testing.T) {
	// Synthetic: a refused connection is unavailability, any other error is
	// passed through unclassified.
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	assert.True(t, errors.Is(transportError(refused), llx.ErrTargetUnavailable))

	other := errors.New("bad request body")
	assert.Equal(t, other, transportError(other))
}

func TestNodeCredentialIDs(t *testing.T) {
	// Measured shape: {"httpHeaderAuth":{"id":"Y2IL...","name":"..."}}, n8n 2.44.6.
	// Synthetic: a template import that names a credential without an id.
	ids := nodeCredentialIDs(map[string]any{
		"httpHeaderAuth":   map[string]any{"id": "Y2ILtunxAFKvFQyE", "name": "mql-verify-httpheader"},
		"slackApi":         map[string]any{"name": "from template"},
		"jiraSoftwareApi":  map[string]any{"id": "AAA", "name": "jira"},
		"unexpectedString": "not a map",
	})
	assert.Equal(t, []string{"AAA", "Y2ILtunxAFKvFQyE"}, ids)
}

func TestSplitList(t *testing.T) {
	// Measured: callerIds "abc123, rgNSSvk5U0wgznVg" as stored by n8n 2.44.6.
	assert.Equal(t, []string{"abc123", "rgNSSvk5U0wgznVg"}, splitList("abc123, rgNSSvk5U0wgznVg"))
	// Synthetic: unset and blank entries.
	assert.Nil(t, splitList(""))
	assert.Equal(t, []string{"a"}, splitList(" , a,,"))
}
