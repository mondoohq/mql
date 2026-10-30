// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func testAdminClient(url string) openai.Client {
	return openai.NewClient(
		option.WithAdminAPIKey("sk-admin-test"),
		option.WithBaseURL(url+"/v1/"),
		option.WithMaxRetries(0),
	)
}

func TestUsageWindowStart(t *testing.T) {
	// Synthetic: late in the UTC day, from a zone east of UTC where the local
	// date is already the next day. The window starts at midnight UTC seven
	// days before the UTC date.
	now := time.Date(2026, 10, 28, 23, 30, 0, 0, time.UTC).In(time.FixedZone("UTC+5", 5*3600))
	want := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC).Unix()
	assert.Equal(t, want, usageWindowStart(now))
}

// usageResponses holds one page per usage endpoint.
//
// Synthetic: the completions, embeddings and images rows are shaped like the
// response examples in the OpenAI Admin API reference for the organization
// usage endpoints, with the grouped dimensions filled in; the embeddings and
// images rows carry null ids the way ungrouped or unattributed rows do.
var usageResponses = map[string]string{
	"/v1/organization/usage/completions": `{
		"object": "page",
		"data": [{
			"object": "bucket",
			"start_time": 1730419200,
			"end_time": 1730505600,
			"results": [{
				"object": "organization.usage.completions.result",
				"input_tokens": 1000,
				"output_tokens": 500,
				"input_cached_tokens": 800,
				"num_model_requests": 5,
				"project_id": "proj_abc",
				"user_id": "user-abc",
				"api_key_id": "key_abc",
				"model": "gpt-4o-mini-2024-07-18",
				"batch": null
			}]
		}],
		"has_more": false,
		"next_page": null
	}`,
	"/v1/organization/usage/embeddings": `{
		"object": "page",
		"data": [{
			"object": "bucket",
			"start_time": 1730419200,
			"end_time": 1730505600,
			"results": [{
				"object": "organization.usage.embeddings.result",
				"input_tokens": 16,
				"num_model_requests": 2,
				"project_id": "proj_abc",
				"user_id": null,
				"api_key_id": "key_def",
				"model": "text-embedding-ada-002-v2"
			}]
		}],
		"has_more": false,
		"next_page": null
	}`,
	"/v1/organization/usage/images": `{
		"object": "page",
		"data": [{
			"object": "bucket",
			"start_time": 1730419200,
			"end_time": 1730505600,
			"results": [{
				"object": "organization.usage.images.result",
				"images": 2,
				"num_model_requests": 2,
				"project_id": "proj_abc",
				"user_id": null,
				"api_key_id": null,
				"model": "dall-e-3"
			}]
		}],
		"has_more": false,
		"next_page": null
	}`,
}

const emptyUsagePage = `{"object": "page", "data": [], "has_more": false, "next_page": null}`

func TestFetchUsageRows(t *testing.T) {
	var mu sync.Mutex
	queried := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "Bearer sk-admin-test", r.Header.Get("Authorization"), r.URL.Path)
		assert.ElementsMatch(t, []string{"project_id", "user_id", "api_key_id", "model"}, q["group_by[]"], r.URL.Path)
		assert.Equal(t, "1d", q.Get("bucket_width"), r.URL.Path)
		assert.Equal(t, "1730419200", q.Get("start_time"), r.URL.Path)
		assert.Equal(t, strconv.Itoa(usageBucketLimit), q.Get("limit"), r.URL.Path)

		mu.Lock()
		queried[r.URL.Path] = true
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		body, ok := usageResponses[r.URL.Path]
		if !ok {
			body = emptyUsagePage
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := testAdminClient(srv.URL)
	rows, err := fetchUsageRows(context.Background(), &client, 1730419200)
	require.NoError(t, err)

	assert.Equal(t, map[string]bool{
		"/v1/organization/usage/completions":          true,
		"/v1/organization/usage/embeddings":           true,
		"/v1/organization/usage/moderations":          true,
		"/v1/organization/usage/images":               true,
		"/v1/organization/usage/audio_speeches":       true,
		"/v1/organization/usage/audio_transcriptions": true,
	}, queried)

	require.Len(t, rows, 3)
	byType := map[string]usageRow{}
	for _, r := range rows {
		byType[r.usageType] = r
	}

	c := byType["completions"]
	assert.Equal(t, int64(1730419200), c.startTime)
	assert.Equal(t, int64(1730505600), c.endTime)
	assert.Equal(t, "proj_abc", c.projectID)
	assert.Equal(t, "user-abc", c.userID)
	assert.Equal(t, "key_abc", c.apiKeyID)
	assert.Equal(t, "gpt-4o-mini-2024-07-18", c.model)
	assert.Equal(t, int64(5), c.requests)
	require.NotNil(t, c.inputTokens)
	require.NotNil(t, c.cachedInputTokens)
	require.NotNil(t, c.outputTokens)
	assert.Equal(t, int64(1000), *c.inputTokens)
	assert.Equal(t, int64(800), *c.cachedInputTokens)
	assert.Equal(t, int64(500), *c.outputTokens)

	e := byType["embeddings"]
	assert.Equal(t, "key_def", e.apiKeyID)
	assert.Empty(t, e.userID, "a null user_id decodes to the empty string the accessor reads as absent")
	require.NotNil(t, e.inputTokens)
	assert.Equal(t, int64(16), *e.inputTokens)
	assert.Nil(t, e.outputTokens, "embeddings produce no output tokens")

	i := byType["images"]
	assert.Equal(t, int64(2), i.requests)
	assert.Empty(t, i.apiKeyID)
	assert.Nil(t, i.inputTokens, "images are not measured in tokens")
}

func TestUsageEntryArgsLeavesUnmeasuredTokensNull(t *testing.T) {
	// Synthetic: an images row, which carries no token counts.
	args := usageEntryArgs(usageRow{usageType: "images", startTime: 1730419200, endTime: 1730505600, requests: 2})
	assert.Nil(t, args["inputTokens"].Value)
	assert.Nil(t, args["cachedInputTokens"].Value)
	assert.Nil(t, args["outputTokens"].Value)
	assert.Equal(t, int64(2), args["requests"].Value)

	// Synthetic: zero output tokens on a completions row is a measurement.
	zero := int64(0)
	args = usageEntryArgs(usageRow{usageType: "completions", outputTokens: &zero})
	assert.Equal(t, int64(0), args["outputTokens"].Value)
}

func TestWalkReportFollowsTheCursor(t *testing.T) {
	// Synthetic: two pages joined by a cursor.
	var cursors []string
	rows, err := walkReport(func(cursor string) ([]int, bool, string, error) {
		cursors = append(cursors, cursor)
		if cursor == "" {
			return []int{1, 2}, true, "page_2", nil
		}
		return []int{3}, false, "", nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, rows)
	assert.Equal(t, []string{"", "page_2"}, cursors)
}

func TestWalkReportStopsOnARepeatedCursor(t *testing.T) {
	// Synthetic: an endpoint that keeps returning the same cursor.
	calls := 0
	rows, err := walkReport(func(cursor string) ([]int, bool, string, error) {
		calls++
		if calls > 10 {
			t.Fatal("walk did not stop on a repeated cursor")
		}
		return []int{calls}, true, "page_stuck", nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, rows)
}

func TestWalkReportReturnsTheFetchError(t *testing.T) {
	_, err := walkReport(func(cursor string) ([]int, bool, string, error) {
		return nil, false, "", errors.New("boom")
	})
	assert.EqualError(t, err, "boom")
}

func TestCostPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/organization/costs", r.URL.Path)
		q := r.URL.Query()
		assert.ElementsMatch(t, []string{"project_id", "line_item"}, q["group_by[]"])
		assert.Equal(t, "1d", q.Get("bucket_width"))
		w.Header().Set("Content-Type", "application/json")
		// Synthetic: the first result follows the costs response example in
		// the OpenAI Admin API reference, grouped by project and line item;
		// the second has no quantity.
		_, _ = w.Write([]byte(`{
			"object": "page",
			"data": [{
				"object": "bucket",
				"start_time": 1730419200,
				"end_time": 1730505600,
				"results": [{
					"object": "organization.costs.result",
					"amount": {"value": 0.06, "currency": "usd"},
					"line_item": "gpt-4o, input_tokens",
					"project_id": "proj_abc",
					"quantity": 24000,
					"quantity_unit": "tokens"
				}, {
					"object": "organization.costs.result",
					"amount": {"value": 1.5, "currency": "usd"},
					"line_item": "file search storage",
					"project_id": null,
					"quantity": null,
					"quantity_unit": null
				}]
			}],
			"has_more": false,
			"next_page": null
		}`))
	}))
	defer srv.Close()

	client := testAdminClient(srv.URL)
	rows, err := walkReport(costPages(context.Background(), &client, 1730419200))
	require.NoError(t, err)
	require.Len(t, rows, 2)

	tokens := rows[0]
	assert.Equal(t, 0.06, tokens.amount)
	assert.Equal(t, "usd", tokens.currency)
	assert.Equal(t, "gpt-4o, input_tokens", tokens.lineItem)
	assert.Equal(t, "proj_abc", tokens.projectID)
	require.NotNil(t, tokens.quantity)
	assert.Equal(t, 24000.0, *tokens.quantity)
	require.NotNil(t, tokens.quantityUnit)
	assert.Equal(t, "tokens", *tokens.quantityUnit)

	storage := rows[1]
	assert.Equal(t, 1.5, storage.amount)
	assert.Empty(t, storage.projectID)
	assert.Nil(t, storage.quantity, "a null quantity stays null, not zero")
	assert.Nil(t, storage.quantityUnit)

	args := costEntryArgs(storage)
	assert.Nil(t, args["quantity"].Value)
	assert.Nil(t, args["quantityUnit"].Value)
}

func TestUsageRowID(t *testing.T) {
	// Synthetic: rows of one day that differ in a single dimension.
	base := usageRow{usageType: "completions", startTime: 1730419200, projectID: "proj_abc", userID: "user-abc", apiKeyID: "key_abc", model: "gpt-4o"}
	variants := []usageRow{base, base, base, base, base, base}
	variants[0].usageType = "embeddings"
	variants[1].startTime = 1730505600
	variants[2].projectID = "proj_def"
	variants[3].userID = ""
	variants[4].apiKeyID = "key_def"
	variants[5].model = "gpt-4o-mini"
	for i, v := range variants {
		assert.NotEqual(t, base.id(), v.id(), "variant %d", i)
	}
}

func TestCostRowID(t *testing.T) {
	// Synthetic: input and output tokens of one model in one project.
	input := costRow{startTime: 1730419200, projectID: "proj_abc", lineItem: "gpt-4o, input_tokens"}
	output := input
	output.lineItem = "gpt-4o, output_tokens"
	assert.NotEqual(t, input.id(), output.id())
	otherProject := input
	otherProject.projectID = ""
	assert.NotEqual(t, input.id(), otherProject.id())
}

func TestUsageEntriesFor(t *testing.T) {
	entry := func(key, user string) *mqlOpenaiUsageEntry {
		return &mqlOpenaiUsageEntry{
			mqlOpenaiUsageEntryInternal: mqlOpenaiUsageEntryInternal{cacheApiKeyId: key, cacheUserId: user},
		}
	}
	// Synthetic: two rows of one key, a row of another key, and a row the
	// report attributes to no key or member.
	day1 := entry("key_abc", "user-abc")
	day2 := entry("key_abc", "user-abc")
	other := entry("key_def", "")
	unattributed := entry("", "")
	all := []any{day1, other, unattributed, day2}

	byKey := func(e *mqlOpenaiUsageEntry) string { return e.cacheApiKeyId }
	byUser := func(e *mqlOpenaiUsageEntry) string { return e.cacheUserId }

	assert.Equal(t, []any{day1, day2}, usageEntriesFor(all, "key_abc", byKey))
	assert.Equal(t, []any{day1, day2}, usageEntriesFor(all, "user-abc", byUser))

	dormant := usageEntriesFor(all, "key_unused", byKey)
	assert.NotNil(t, dormant, "a key without usage reads as an empty list, not null")
	assert.Empty(t, dormant)

	assert.Empty(t, usageEntriesFor(all, "", byKey), "an empty id never claims unattributed rows")
}

func TestClassifyReportError(t *testing.T) {
	assert.ErrorIs(t, classifyReportError(&openai.Error{StatusCode: http.StatusForbidden}, "usage report"), llx.ErrForbidden)
	assert.ErrorIs(t, classifyReportError(&openai.Error{StatusCode: http.StatusUnauthorized}, "usage report"), llx.ErrUnauthenticated)

	// A transport failure and a server error say nothing about access.
	for _, err := range []error{
		fmt.Errorf("dial tcp: connection refused"),
		&openai.Error{StatusCode: http.StatusInternalServerError},
	} {
		got := classifyReportError(err, "usage report")
		assert.NotErrorIs(t, got, llx.ErrForbidden)
		assert.NotErrorIs(t, got, llx.ErrUnauthenticated)
	}
}
