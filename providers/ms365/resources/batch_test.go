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
	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
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
// batchMaxConcurrency chunks ahead of what it has handed over, so a fetch over
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
				limit := (len(handedOver) + batchMaxConcurrency) * batchChunkSize
				assert.LessOrEqualf(t, sent, limit, "more than %d chunks were sent ahead of the handover of chunk %d", batchMaxConcurrency, chunk)
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

// Chunks are sent concurrently, never more than batchMaxConcurrency at a time,
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
	assert.Equal(t, batchMaxConcurrency, f.maxInflight, "chunks should overlap up to the limit")
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

// A heavily throttled chunk pauses sending for its Retry-After, or a backoff
// that doubles while chunks keep coming back that way, and drops to one call
// in flight; a run of chunks without heavy throttling raises the limit again,
// one at a time. A lightly throttled chunk neither pauses nor lowers the limit.
func TestBatchPacer(t *testing.T) {
	backoff := batchRetryBackoff
	batchRetryBackoff = time.Second
	t.Cleanup(func() { batchRetryBackoff = backoff })

	now := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	p := newBatchPacer(2)
	assert.Equal(t, 2, p.limit)
	assert.True(t, p.ready(now))

	assert.False(t, p.observe(now, now, 1, batchChunkSize, 10*time.Second), "one throttled key of a chunk is no reason to pause")
	assert.False(t, p.observe(now, now, 9, 19, 0))
	assert.Equal(t, 2, p.limit)

	assert.False(t, p.observe(now, now, 10, 19, 10*time.Second), "one heavily throttled chunk does not pause the fetch")
	assert.Equal(t, 1, p.limit, "but it drops to one call in flight")
	assert.True(t, p.ready(now))

	// half of the window heavily throttled pauses the fetch
	for range batchPauseWindow/2 - 2 {
		assert.False(t, p.observe(now, now, batchChunkSize, batchChunkSize, 0))
	}
	assert.True(t, p.observe(now, now, batchChunkSize, batchChunkSize, 0))
	assert.False(t, p.ready(now.Add(9*time.Second)))
	assert.True(t, p.ready(now.Add(10*time.Second)), "the pause is the longest Retry-After in the window")

	// chunks that were sent before the pause ended say nothing about now
	for range 2 * batchPauseWindow {
		assert.False(t, p.observe(now.Add(time.Second), now, batchChunkSize, batchChunkSize, 0))
	}
	assert.Equal(t, now.Add(10*time.Second), p.pausedUntil)

	heavyWindow := func(now time.Time, retryAfter time.Duration) bool {
		for range batchPauseWindow/2 - 1 {
			require.False(t, p.observe(now, now, batchChunkSize, batchChunkSize, retryAfter))
		}
		return p.observe(now, now, batchChunkSize, batchChunkSize, retryAfter)
	}

	// without a Retry-After the pause doubles while pauses follow one another
	now = now.Add(10 * time.Second)
	assert.True(t, heavyWindow(now, 0))
	assert.Equal(t, now.Add(2*time.Second), p.pausedUntil)
	now = now.Add(2 * time.Second)
	assert.True(t, heavyWindow(now, 0))
	assert.Equal(t, now.Add(4*time.Second), p.pausedUntil)
	now = now.Add(4 * time.Second)
	assert.True(t, heavyWindow(now, 10*time.Hour))
	assert.Equal(t, now.Add(batchMaxRetryWait), p.pausedUntil, "the pause is capped")

	// a chunk that gets through resets the backoff
	now = now.Add(batchMaxRetryWait)
	p.observe(now, now, 1, batchChunkSize, 0)
	assert.True(t, heavyWindow(now, 0))
	assert.Equal(t, now.Add(time.Second), p.pausedUntil)

	// batchRampUpChunks chunks in a row without heavy throttling raise the
	// limit by one, up to max
	now = now.Add(time.Second)
	for range batchRampUpChunks - 1 {
		p.observe(now, now, 0, batchChunkSize, 0)
	}
	assert.Equal(t, 1, p.limit)
	p.observe(now, now, 1, batchChunkSize, 0)
	assert.Equal(t, 2, p.limit, "light throttling still counts towards the ramp-up")
	for range 2 * batchRampUpChunks {
		p.observe(now, now, 0, batchChunkSize, 0)
	}
	assert.Equal(t, 2, p.limit, "never above max")

	// a failed $batch call pauses for the backoff
	p.failed(now)
	assert.Equal(t, 1, p.limit)
	assert.Equal(t, now.Add(time.Second), p.pausedUntil)
}

// A throttled key waits out its own Retry-After; the keys that got through
// keep going in the meantime.
func TestBatchEachResendsAThrottledKeyAfterItsRetryAfter(t *testing.T) {
	keys := make([]string, 4*batchChunkSize)
	routes := map[string]fakeRoute{}
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	f := newFakeGraph(t, routes)
	f.throttle = map[string]int{"/users/u000": 1}
	f.retryAfter = "1"
	client := f.client()
	ctx := context.Background()

	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error { return nil })
	require.NoError(t, err)
	assert.Empty(t, errs)

	var sends []time.Time
	for i, step := range f.steps {
		if strings.HasSuffix(step, "/users/u000") {
			sends = append(sends, f.stepTimes[i])
		}
	}
	require.Len(t, sends, 2)
	assert.GreaterOrEqual(t, sends[1].Sub(sends[0]), time.Second, "resent before its Retry-After")
	last := f.steps[len(f.steps)-1]
	assert.True(t, strings.HasSuffix(last, "/users/u000"), "every other key went out while u000 waited, last sent was %s", last)
}

// Graph throttling a whole chunk now and then must not stop the fetch. Hosted
// scans of ordinary tenants ran three to eight times longer when every such
// chunk paused everything for its Retry-After.
func TestBatchEachDoesNotPauseOnIsolatedHeavyThrottling(t *testing.T) {
	const chunks = 40
	keys := make([]string, chunks*batchChunkSize)
	routes := map[string]fakeRoute{}
	f := newFakeGraph(t, routes)
	f.throttle = map[string]int{}
	f.retryAfter = "1"
	for i := range keys {
		keys[i] = fmt.Sprintf("u%04d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
		if (i/batchChunkSize)%4 == 0 {
			f.throttle["/users/"+keys[i]] = 1
		}
	}
	client := f.client()
	ctx := context.Background()

	seen := map[string]bool{}
	start := time.Now()
	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			seen[key] = true
			return nil
		})
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Len(t, seen, len(keys))
	// Ten heavily throttled chunks with a one-second Retry-After each: pausing
	// for every one of them takes at least ten seconds.
	assert.Less(t, time.Since(start), 4*time.Second, "the fetch paused for isolated heavily throttled chunks")
}

// When Graph keeps throttling most of what is sent, the whole fetch pauses:
// nothing new goes out until the pause is over.
func TestBatchEachPausesUnderSustainedHeavyThrottling(t *testing.T) {
	backoff := batchRetryBackoff
	batchRetryBackoff = 300 * time.Millisecond
	t.Cleanup(func() { batchRetryBackoff = backoff })

	heavy := batchPauseWindow / 2
	keys := make([]string, (heavy+4)*batchChunkSize)
	routes := map[string]fakeRoute{}
	f := newFakeGraph(t, routes)
	f.throttle = map[string]int{}
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
		if i < heavy*batchChunkSize {
			f.throttle["/users/"+keys[i]] = 1
		}
	}
	client := f.client()
	ctx := context.Background()

	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error { return nil })
	require.NoError(t, err)
	assert.Empty(t, errs)

	firstSend := func(key string) time.Time {
		i := slices.IndexFunc(f.steps, func(step string) bool { return strings.HasSuffix(step, "/users/"+key) })
		require.GreaterOrEqual(t, i, 0, key)
		return f.stepTimes[i]
	}
	lastHeavy := firstSend(keys[heavy*batchChunkSize-1])
	firstFresh := firstSend(keys[heavy*batchChunkSize])
	assert.GreaterOrEqual(t, firstFresh.Sub(lastHeavy), batchRetryBackoff, "a new chunk went out during the pause")
}

// Graph throttling the odd sub-request must not pause the fetch: those keys
// wait out their backoff while everything else keeps going.
func TestBatchEachDoesNotPauseOnLightThrottling(t *testing.T) {
	backoff := batchRetryBackoff
	batchRetryBackoff = 500 * time.Millisecond
	t.Cleanup(func() { batchRetryBackoff = backoff })

	keys := make([]string, 6*batchChunkSize)
	routes := map[string]fakeRoute{}
	f := newFakeGraph(t, routes)
	f.throttle = map[string]int{}
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
		if i%batchChunkSize == 0 {
			f.throttle["/users/"+keys[i]] = 1
		}
	}
	client := f.client()
	ctx := context.Background()

	seen := map[string]bool{}
	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			seen[key] = true
			return nil
		})
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Len(t, seen, len(keys))
	require.Len(t, f.steps, len(keys)+6)
	assert.Less(t, f.stepTimes[len(keys)-1].Sub(f.stepTimes[0]), batchRetryBackoff, "every key was sent once before the backoff ran out")
	assert.GreaterOrEqual(t, f.stepTimes[len(keys)].Sub(f.stepTimes[0]), batchRetryBackoff, "a throttled key was resent before its backoff")
}

// A $batch call that fails as a whole puts its keys back into the queue; the
// fetch still gets every key.
func TestBatchEachResendsFailedBatchCalls(t *testing.T) {
	backoff := batchRetryBackoff
	batchRetryBackoff = time.Millisecond
	t.Cleanup(func() { batchRetryBackoff = backoff })

	keys := make([]string, 4*batchChunkSize)
	routes := map[string]fakeRoute{}
	for i := range keys {
		keys[i] = fmt.Sprintf("u%03d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	f := newFakeGraph(t, routes)
	f.failBatches = 3
	client := f.client()
	ctx := context.Background()

	seen := map[string]int{}
	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			seen[key]++
			return nil
		})
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Len(t, seen, len(keys))
	for key, count := range seen {
		assert.Equalf(t, 1, count, "%s handed over more than once", key)
	}
}

// A fetch whose $batch calls keep failing gives up after batchMaxSendFailures
// failures in a row and returns the error.
func TestBatchEachGivesUpAfterRepeatedFailures(t *testing.T) {
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
	f.failBatches = 1000
	client := f.client()
	ctx := context.Background()

	_, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error { return nil })
	require.Error(t, err)
	assert.LessOrEqual(t, f.batchCalls, batchMaxSendFailures+batchMaxConcurrency, "no call is sent after giving up")
}

// A tenant whose limit is one $batch call at a time throttles every
// sub-request of a second concurrent call. batchEach must settle at one call
// in flight and fetch every key, instead of resending everything throttled at
// full speed until the retries run out.
func TestBatchEachSettlesUnderRateLimit(t *testing.T) {
	backoff := batchRetryBackoff
	batchRetryBackoff = time.Millisecond
	t.Cleanup(func() { batchRetryBackoff = backoff })

	keys := make([]string, 3*batchRampUpChunks*batchChunkSize)
	routes := map[string]fakeRoute{}
	for i := range keys {
		keys[i] = fmt.Sprintf("u%05d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	f := newFakeGraph(t, routes)
	f.rateLimit = 1
	f.delay = time.Millisecond
	client := f.client()
	ctx := context.Background()

	seen := map[string]bool{}
	errs, _, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			seen[key] = true
			return nil
		})
	require.NoError(t, err)
	assert.Empty(t, errs, "no key may run out of retries")
	assert.Len(t, seen, len(keys))
	resent := len(f.steps) - len(keys)
	assert.LessOrEqualf(t, resent, 10*batchChunkSize, "%d sub-requests resent; throttling should only cost the occasional ramp-up probe", resent)
}

func TestBatchEndpointNamesTheCallWithoutIDs(t *testing.T) {
	f := newFakeGraph(t, nil)
	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(f.srv.URL + "/beta")
	client := msgraphsdkgo.NewGraphServiceClient(adapter)

	reqInfo, err := client.Users().ByUserId("8a1c2d3e-0000-4000-8000-000000000001").Authentication().Methods().ToGetRequestInformation(context.Background(), nil)
	require.NoError(t, err)
	got := batchEndpoint(adapter, reqInfo)
	assert.Equal(t, "beta/users/{user-id}/authentication/methods", got)
	assert.NotContains(t, got, "8a1c2d3e")

	reqInfo, err = f.client().Users().ByUserId("someone").Settings().ToGetRequestInformation(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "v1.0/users/{user-id}/settings", batchEndpoint(f.client().GetAdapter(), reqInfo))
}
