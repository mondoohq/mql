// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePager replays fixed pages of ids the way an openai-go auto-pager hands
// out items, so the walk can be driven without a server.
type fakePager struct {
	items []string
	idx   int
	err   error
}

func (p *fakePager) Next() bool {
	if p.idx >= len(p.items) {
		return false
	}
	p.idx++
	return true
}

func (p *fakePager) Current() string { return p.items[p.idx-1] }
func (p *fakePager) Err() error      { return p.err }

func TestWalkPages(t *testing.T) {
	pager := &fakePager{items: []string{"a", "b", "c"}}
	var got []string
	require.NoError(t, walkPages[string](pager, func(s string) string { return s }, func(s string) error {
		got = append(got, s)
		return nil
	}))
	assert.Equal(t, []string{"a", "b", "c"}, got)
}

func TestWalkPagesStopsOnARepeatedIdentifier(t *testing.T) {
	// An endpoint that ignores its `after` cursor answers with the same page
	// forever, and the SDK auto-pager keeps asking while the response says
	// has_more. Without this guard the scan hangs instead of failing.
	pager := &fakePager{items: []string{"a", "b", "a", "b", "a", "b"}}
	var got []string
	require.NoError(t, walkPages[string](pager, func(s string) string { return s }, func(s string) error {
		got = append(got, s)
		return nil
	}))
	assert.Equal(t, []string{"a", "b"}, got, "the walk stops where the endpoint stopped advancing")
}

func TestWalkPagesReportsThePagerError(t *testing.T) {
	pager := &fakePager{items: []string{"a"}, err: assert.AnError}
	err := walkPages[string](pager, func(s string) string { return s }, func(s string) error { return nil })
	assert.ErrorIs(t, err, assert.AnError,
		"a failed page has to surface as an error; a short list satisfies every assertion made about it")
}

func TestWalkPagesReportsAVisitError(t *testing.T) {
	pager := &fakePager{items: []string{"a", "b"}}
	visited := 0
	err := walkPages[string](pager, func(s string) string { return s }, func(s string) error {
		visited++
		return assert.AnError
	})
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, visited)
}

// testClient points a real SDK client at a test server, so the walk runs
// through the same pagination the provider uses at runtime.
func testClient(url string) openai.Client {
	return openai.NewClient(
		option.WithAPIKey("sk-proj-test"),
		option.WithBaseURL(url+"/v1/"),
		option.WithMaxRetries(0),
	)
}

func writeBatchPage(t *testing.T, w http.ResponseWriter, ids []string, hasMore bool) {
	t.Helper()
	data := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		data = append(data, map[string]any{
			"id":       id,
			"object":   "batch",
			"endpoint": "/v1/chat/completions",
			"status":   "completed",
		})
	}
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
		"object":   "list",
		"data":     data,
		"has_more": hasMore,
	}))
}

func TestWalkPagesFollowsTheCursorAcrossPages(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/batches", r.URL.Path)
		switch requests.Add(1) {
		case 1:
			assert.Empty(t, r.URL.Query().Get("after"), "the first page asks for no cursor")
			writeBatchPage(t, w, []string{"batch_0000", "batch_0001"}, true)
		default:
			assert.Equal(t, "batch_0001", r.URL.Query().Get("after"),
				"the next page continues from the last item of the previous one")
			writeBatchPage(t, w, []string{"batch_0002"}, false)
		}
	}))
	defer srv.Close()

	client := testClient(srv.URL)
	var ids []string
	err := walkPages(
		client.Batches.ListAutoPaging(context.Background(), openai.BatchListParams{}),
		func(b openai.Batch) string { return b.ID },
		func(b openai.Batch) error {
			ids = append(ids, b.ID)
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"batch_0000", "batch_0001", "batch_0002"}, ids,
		"a truncated walk under-reports, which is the direction that makes an audit pass")
	assert.Equal(t, int32(2), requests.Load())
}

func TestWalkPagesTerminatesOnAStuckCursor(t *testing.T) {
	// The server ignores `after` and keeps claiming there is more. The SDK
	// auto-pager on its own never stops here.
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 100 {
			t.Error("the walk did not terminate on a stuck cursor")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeBatchPage(t, w, []string{"batch_0000", "batch_0001"}, true)
	}))
	defer srv.Close()

	client := testClient(srv.URL)
	var ids []string
	err := walkPages(
		client.Batches.ListAutoPaging(context.Background(), openai.BatchListParams{}),
		func(b openai.Batch) string { return b.ID },
		func(b openai.Batch) error {
			ids = append(ids, b.ID)
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"batch_0000", "batch_0001"}, ids,
		"each batch is reported once, not multiplied by however many pages the endpoint serves")
	assert.LessOrEqual(t, requests.Load(), int32(3))
}

func TestIsNotFoundDoesNotMatchATransportError(t *testing.T) {
	// A 404 means "not configured", which is a legitimate null. A network
	// failure is not, and treating it as one degrades a field to null and lets
	// an audit pass on data that was never read.
	assert.True(t, isNotFound(&openai.Error{StatusCode: http.StatusNotFound}))
	assert.False(t, isNotFound(&openai.Error{StatusCode: http.StatusInternalServerError}))
	assert.False(t, isNotFound(fmt.Errorf("dial tcp: connection refused")))
	assert.False(t, isNotFound(nil))
}

// The change record is read out of the raw document the SDK keeps alongside
// each decoded item. Items arriving inside a list response are decoded by the
// pager rather than individually, so this pins that the raw document survives
// that path: if it did not, every entry's details would silently read null.
func TestAuditLogDetailsSurviveTheListDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/organization/audit_logs", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"object": "list",
			"has_more": false,
			"data": [` + sessionActorEntry + `]
		}`))
	}))
	defer srv.Close()

	client := testClient(srv.URL)
	iter := client.Admin.Organization.AuditLogs.ListAutoPaging(context.Background(),
		openai.AdminOrganizationAuditLogListParams{})
	require.True(t, iter.Next())
	entry := iter.Current()
	require.NoError(t, iter.Err())

	require.NotEmpty(t, entry.RawJSON(), "the raw document has to reach the detail extraction")
	details, err := auditLogDetails(entry.RawJSON(), string(entry.Type))
	require.NoError(t, err)
	payload, ok := details.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "key_0000", payload["id"])
	assert.Equal(t, "proj_0000", entry.Project.ID, "the project scope is what makes the entry attributable")
	assert.Equal(t, "user_0000", auditLogActorUserID(entry.Actor))
}
