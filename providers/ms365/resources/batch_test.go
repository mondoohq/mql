// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	msgraphgocore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batchStatusHasNoBody gates whether a sub-response reaches the deserializer.
// Getting it wrong in either direction is a real bug: too narrow and a
// body-less success panics the parse, too wide and a real payload is silently
// dropped.
func TestBatchStatusHasNoBody(t *testing.T) {
	tests := []struct {
		name string
		code int32
		want bool
	}{
		{"204 no content", http.StatusNoContent, true},
		{"205 reset content", http.StatusResetContent, true},
		{"200 ok carries a body", http.StatusOK, false},
		{"201 created carries a body", http.StatusCreated, false},
		{"202 accepted carries a body", http.StatusAccepted, false},
		{"206 partial content carries a body", http.StatusPartialContent, false},
		{"403 is handled by the non-2xx guard", http.StatusForbidden, false},
		{"404 is handled by the non-2xx guard", http.StatusNotFound, false},
		{"429 is handled by the non-2xx guard", http.StatusTooManyRequests, false},
		{"zero value", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, batchStatusHasNoBody(tc.code))
		})
	}
}

// The two guards in batchGet must partition every status code: a non-2xx is an
// error, a body-less 2xx is an absence, and everything else is parsed. A code
// falling through both that has no body is exactly the 204 case that panicked.
func TestBatchStatusGuardsPartitionAllCodes(t *testing.T) {
	isFailure := func(code int32) bool { return code < 200 || code >= 300 }

	for code := int32(100); code < 600; code++ {
		failure := isFailure(code)
		noBody := batchStatusHasNoBody(code)
		assert.Falsef(t, failure && noBody,
			"status %d is classified as both a failure and a body-less success", code)

		if noBody {
			assert.Truef(t, code >= 200 && code < 300,
				"only a 2xx should reach the body-less branch, got %d", code)
		}
	}

	assert.True(t, batchStatusHasNoBody(http.StatusNoContent),
		"204 must be caught before the parse: it is a success, so the non-2xx guard lets it through, "+
			"and GetBatchResponseById panics on the absent body")
}

// batchEach must hand chunks over as they return and never send more than
// batchConcurrency chunks ahead of what it has handed over, so a fetch over
// every user of a large tenant holds at most that many chunks of raw
// responses. A failed sub-request or a failing callback is recorded for its
// key alone.
func TestBatchEachStreamsChunks(t *testing.T) {
	const n = 8*batchChunkSize + 7
	routes := map[string]fakeRoute{}
	keys := make([]string, n)
	index := make(map[string]int, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		index[keys[i]] = i
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	routes["/users/u003"] = fakeRoute{status: http.StatusForbidden, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`}
	f := newFakeGraph(t, routes)
	client := f.client()
	ctx := context.Background()

	seen := map[string]bool{}
	handedOver := map[int]bool{} // chunks that reached the callback
	errs, statuses, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			assert.Equal(t, key, *u.GetId())
			seen[key] = true
			f.mu.Lock()
			sent := len(f.steps)
			ownSent := slices.ContainsFunc(f.steps, func(step string) bool { return strings.HasSuffix(step, "/users/"+key) })
			f.mu.Unlock()
			assert.Truef(t, ownSent, "%s was handed over before its request was sent", key)
			if chunk := index[key] / batchChunkSize; !handedOver[chunk] {
				limit := (len(handedOver) + batchConcurrency) * batchChunkSize
				assert.LessOrEqualf(t, sent, limit, "more than %d chunks were sent ahead of the handover of chunk %d", batchConcurrency, chunk)
				handedOver[chunk] = true
			}
			if key == "u040" {
				return errors.New("convert failed")
			}
			return nil
		})
	require.NoError(t, err)

	assert.Len(t, seen, n-1, "every key but the failed one reaches the callback")
	assert.Equal(t, int32(http.StatusForbidden), statuses["u003"])
	assert.EqualError(t, errs["u003"], "batch request failed with status 403")
	assert.EqualError(t, errs["u040"], "convert failed")
	assert.Len(t, errs, 2)
	assert.Len(t, statuses, n)
}

// Chunks are sent concurrently, never more than batchConcurrency at a time,
// and every key is handed over exactly once whatever order they return in.
func TestBatchEachSendsChunksConcurrently(t *testing.T) {
	const n = 10 * batchChunkSize
	routes := map[string]fakeRoute{}
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	f := newFakeGraph(t, routes)
	f.delay = 50 * time.Millisecond
	client := f.client()
	ctx := context.Background()

	seen := map[string]int{}
	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			seen[key]++ // unsynchronized on purpose: each runs on the calling goroutine
			return nil
		})
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Len(t, seen, n)
	for key, count := range seen {
		assert.Equalf(t, 1, count, "%s handed over more than once", key)
	}
	assert.Equal(t, batchConcurrency, f.maxInflight, "chunks should overlap up to the limit")
}

// A chunk whose request cannot be built ends the fetch with that error, no
// later chunk is built, and batchEach returns once the chunks already in
// flight have finished.
func TestBatchEachStopsOnBuildError(t *testing.T) {
	keys := make([]string, 6*batchChunkSize)
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
	}
	f := newFakeGraph(t, map[string]fakeRoute{})
	client := f.client()
	ctx := context.Background()

	built := 0
	_, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			built++
			if built > 2*batchChunkSize {
				return nil, errors.New("build failed")
			}
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error { return nil })
	require.EqualError(t, err, "build failed")
	assert.LessOrEqual(t, built, 2*batchChunkSize+1, "no chunk is built after the failure")
}

// Graph throttles single sub-requests inside a $batch call that itself
// succeeds, so the SDK's retry handler never sees it. batchEach resends
// those keys until they succeed, and only records a key as failed once its
// retries are used up.
func TestBatchEachResendsThrottledSubRequests(t *testing.T) {
	backoff := batchRetryBackoff
	batchRetryBackoff = time.Millisecond
	t.Cleanup(func() { batchRetryBackoff = backoff })

	keys := make([]string, 2*batchChunkSize)
	routes := map[string]fakeRoute{}
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	f := newFakeGraph(t, routes)
	f.throttle = map[string]int{
		"/users/u001": 1,
		"/users/u020": 3,
		"/users/u030": batchMaxRetries + 1, // never gets through
	}
	client := f.client()
	ctx := context.Background()

	seen := map[string]int{}
	errs, statuses, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			seen[key]++
			return nil
		})
	require.NoError(t, err)

	assert.Equal(t, 1, seen["u001"])
	assert.Equal(t, 1, seen["u020"])
	assert.Equal(t, int32(http.StatusOK), statuses["u020"], "the status is the one of the last attempt")
	assert.NotContains(t, seen, "u030")
	assert.EqualError(t, errs["u030"], "batch request failed with status 429")
	assert.Len(t, errs, 1)
	assert.Len(t, seen, len(keys)-1)
	for key, count := range seen {
		assert.Equalf(t, 1, count, "%s handed over more than once", key)
	}
}

func TestBatchRetryAfter(t *testing.T) {
	item := func(headers map[string]string) msgraphgocore.BatchItem {
		i := msgraphgocore.NewBatchItem()
		i.SetHeaders(headers)
		return i
	}
	assert.Equal(t, 7*time.Second, batchRetryAfter(item(map[string]string{"Retry-After": "7"})))
	assert.Equal(t, 3*time.Second, batchRetryAfter(item(map[string]string{"retry-after": " 3 "})))
	assert.Zero(t, batchRetryAfter(item(map[string]string{"Content-Type": "application/json"})))
	assert.Zero(t, batchRetryAfter(item(map[string]string{"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})))
	assert.Zero(t, batchRetryAfter(nil))
}
