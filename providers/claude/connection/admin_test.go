// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlexibleStringSlice_UnmarshalJSON(t *testing.T) {
	// Decoded via a struct field so the test exercises the same code path
	// encoding/json uses for AdminDataResidency.AllowedInferenceGeos.
	type wrap struct {
		Geos FlexibleStringSlice `json:"geos"`
	}

	tests := []struct {
		name string
		json string
		want []string
	}{
		{"array", `{"geos": ["us", "eu"]}`, []string{"us", "eu"}},
		{"single string", `{"geos": "us"}`, []string{"us"}},
		{"empty array", `{"geos": []}`, []string{}},
		// Regression: a JSON null (an unrestricted workspace) must decode to an
		// empty slice, never [""]. json.Unmarshal of null into a string is a
		// no-op that returns no error, so without an explicit guard the string
		// branch wins and produces a bogus one-element slice.
		{"null", `{"geos": null}`, nil},
		{"absent", `{}`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w wrap
			require.NoError(t, json.Unmarshal([]byte(tt.json), &w))
			assert.Equal(t, tt.want, []string(w.Geos))
		})
	}
}

func TestAdminRateLimit_LimitValue(t *testing.T) {
	rl := &AdminRateLimit{
		Limits: []AdminRateLimiter{
			{Type: "requests_per_minute", Value: 1000},
			{Type: "output_tokens_per_minute", Value: 50000},
		},
	}

	assert.Equal(t, int64(1000), rl.LimitValue("requests_per_minute"))
	assert.Equal(t, int64(50000), rl.LimitValue("output_tokens_per_minute"))
	// Missing limiter types report 0 rather than panicking.
	assert.Equal(t, int64(0), rl.LimitValue("input_tokens_per_minute_cache_aware"))
	assert.Equal(t, int64(0), rl.LimitValue(""))
}

// item is a minimal payload used by the pagination tests.
type item struct {
	ID string `json:"id"`
}

func TestPaginate_AfterIDCursor(t *testing.T) {
	var seenCursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCursors = append(seenCursors, r.URL.Query().Get("after_id"))
		// Every request must carry the limit and the correct path.
		assert.Equal(t, "100", r.URL.Query().Get("limit"))
		assert.Equal(t, "/v1/things", r.URL.Path)

		var resp paginatedResponse[item]
		switch r.URL.Query().Get("after_id") {
		case "":
			resp = paginatedResponse[item]{Data: []item{{"a"}, {"b"}}, HasMore: true, LastID: "b"}
		case "b":
			resp = paginatedResponse[item]{Data: []item{{"c"}}, HasMore: false, LastID: "c"}
		default:
			t.Fatalf("unexpected after_id cursor %q", r.URL.Query().Get("after_id"))
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	got, err := paginate[item](context.Background(), c, "/v1/things")
	require.NoError(t, err)

	assert.Equal(t, []item{{"a"}, {"b"}, {"c"}}, got)
	// First page has no cursor; the second page must forward last_id from page one.
	assert.Equal(t, []string{"", "b"}, seenCursors)
}

func TestPaginate_StopsWhenHasMoreFalse(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := paginatedResponse[item]{Data: []item{{"only"}}, HasMore: false, LastID: "only"}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	got, err := paginate[item](context.Background(), c, "/v1/things")
	require.NoError(t, err)

	assert.Equal(t, []item{{"only"}}, got)
	assert.Equal(t, 1, calls, "must not request a second page when has_more is false")
}

func TestPaginatePageToken_NextPageCursor(t *testing.T) {
	var seenPages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPages = append(seenPages, r.URL.Query().Get("page"))

		next := "page-2"
		var resp pageTokenResponse[item]
		switch r.URL.Query().Get("page") {
		case "":
			resp = pageTokenResponse[item]{Data: []item{{"a"}}, HasMore: true, NextPage: &next}
		case "page-2":
			resp = pageTokenResponse[item]{Data: []item{{"b"}}, HasMore: false, NextPage: nil}
		default:
			t.Fatalf("unexpected page cursor %q", r.URL.Query().Get("page"))
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	// A base path that already carries a query string, to exercise the
	// "?"-vs-"&" separator logic.
	got, err := paginatePageToken[item](context.Background(), c, "/v1/report?bucket_width=1d")
	require.NoError(t, err)

	assert.Equal(t, []item{{"a"}, {"b"}}, got)
	assert.Equal(t, []string{"", "page-2"}, seenPages)
}

func TestPaginatePageToken_StopsOnEmptyNextPage(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		empty := ""
		resp := pageTokenResponse[item]{Data: []item{{"a"}}, HasMore: true, NextPage: &empty}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	got, err := paginatePageToken[item](context.Background(), c, "/v1/report")
	require.NoError(t, err)

	assert.Equal(t, []item{{"a"}}, got)
	assert.Equal(t, 1, calls, "an empty next_page string must terminate pagination")
}

func TestDoRequest_ErrorStatusPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth headers must be set on every request.
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, adminAPIVersion, r.Header.Get("anthropic-version"))
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	_, err := c.get(context.Background(), "/v1/things")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestListUsageReport_GroupsByCaller(t *testing.T) {
	var groupBy []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/organizations/usage_report/messages", r.URL.Path)
		groupBy = r.URL.Query()["group_by[]"]
		// Synthetic: the first result is the response example in the Admin
		// API reference for GET /v1/organizations/usage_report/messages; the
		// second is Console usage in the default workspace.
		_, _ = w.Write([]byte(`{
			"data": [{
				"starting_at": "2025-08-01T00:00:00Z",
				"ending_at": "2025-08-02T00:00:00Z",
				"results": [{
					"uncached_input_tokens": 1500,
					"cache_read_input_tokens": 200,
					"output_tokens": 500,
					"model": "claude-opus-5-5",
					"service_tier": "batch",
					"workspace_id": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ",
					"api_key_id": "apikey_01Rj2N8SVvo6BePZj99NhmiT",
					"account_id": "user_01WCz1FkmYMm4gnmykNKUu3Q",
					"service_account_id": "svac_01Hk3R9TWxq7CfQak00OiVw4"
				}, {
					"uncached_input_tokens": 10,
					"cache_read_input_tokens": 0,
					"output_tokens": 5,
					"model": "claude-opus-5-5",
					"service_tier": "standard",
					"workspace_id": null,
					"api_key_id": null,
					"account_id": null,
					"service_account_id": null
				}]
			}],
			"has_more": false,
			"next_page": null
		}`))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	got, err := c.ListUsageReport(context.Background())
	require.NoError(t, err)

	// The API returns a dimension as null unless the request groups by it.
	assert.ElementsMatch(t, []string{
		"workspace_id", "model", "service_tier", "api_key_id", "account_id", "service_account_id",
	}, groupBy)
	require.Len(t, got, 1)
	require.Len(t, got[0].Results, 2)
	res := got[0].Results[0]
	assert.Equal(t, "batch", res.ServiceTier)
	assert.Equal(t, "claude-opus-5-5", res.Model)
	assert.Equal(t, "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ", res.WorkspaceID)
	assert.Equal(t, "apikey_01Rj2N8SVvo6BePZj99NhmiT", res.APIKeyID)
	assert.Equal(t, "user_01WCz1FkmYMm4gnmykNKUu3Q", res.AccountID)
	assert.Equal(t, "svac_01Hk3R9TWxq7CfQak00OiVw4", res.ServiceAccountID)

	// Synthetic: Console usage in the default workspace carries null ids,
	// which decode to the empty string the resources treat as absent.
	console := got[0].Results[1]
	assert.Empty(t, console.APIKeyID)
	assert.Empty(t, console.AccountID)
	assert.Empty(t, console.ServiceAccountID)
	assert.Empty(t, console.WorkspaceID)
}

func TestListCostReport_GroupsByDescription(t *testing.T) {
	var groupBy []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/organizations/cost_report", r.URL.Path)
		groupBy = r.URL.Query()["group_by[]"]
		// Synthetic: one result shaped like the response example in the
		// Admin API reference for GET /v1/organizations/cost_report.
		_, _ = w.Write([]byte(`{
			"data": [{
				"starting_at": "2025-08-01T00:00:00Z",
				"ending_at": "2025-08-02T00:00:00Z",
				"results": [{
					"amount": "123.78912",
					"currency": "USD",
					"cost_type": "tokens",
					"description": "Claude Opus 5.5 Usage - Input Tokens",
					"model": "claude-opus-5-5",
					"workspace_id": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"
				}]
			}],
			"has_more": false,
			"next_page": null
		}`))
	}))
	defer srv.Close()

	c := NewAdminClient("test-key", srv.URL)
	got, err := c.ListCostReport(context.Background())
	require.NoError(t, err)

	// The API returns cost_type and model as null unless the request groups by description.
	assert.ElementsMatch(t, []string{"workspace_id", "description"}, groupBy)
	require.Len(t, got, 1)
	require.Len(t, got[0].Results, 1)
	res := got[0].Results[0]
	assert.Equal(t, "tokens", res.CostType)
	assert.Equal(t, "claude-opus-5-5", res.Model)
	assert.Equal(t, "Claude Opus 5.5 Usage - Input Tokens", res.Description)
}
