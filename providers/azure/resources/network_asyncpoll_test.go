// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingBody wraps a response body so a test can see whether the caller closed
// it. A leaked body is invisible in the returned data -- the only way to catch it
// is to watch the close.
type countingBody struct {
	io.ReadCloser
	closed *atomic.Int32
}

func (c countingBody) Close() error {
	c.closed.Add(1)
	return c.ReadCloser.Close()
}

// bodyTracker wraps a RoundTripper and records one close counter per response, in
// the order the responses came back.
type bodyTracker struct {
	rt       http.RoundTripper
	mu       sync.Mutex
	counters []*atomic.Int32
}

func (b *bodyTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := b.rt.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	counter := &atomic.Int32{}
	b.mu.Lock()
	b.counters = append(b.counters, counter)
	b.mu.Unlock()
	resp.Body = countingBody{ReadCloser: resp.Body, closed: counter}
	return resp, nil
}

func (b *bodyTracker) closes() []int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]int32, 0, len(b.counters))
	for _, c := range b.counters {
		out = append(out, c.Load())
	}
	return out
}

func trackedClient(t *testing.T) (*http.Client, *bodyTracker) {
	t.Helper()
	tracker := &bodyTracker{rt: http.DefaultTransport}
	return &http.Client{Transport: tracker, Timeout: 10 * time.Second}, tracker
}

// pollTestSetup shortens the poll interval so a test does not sleep through the
// production two seconds.
func pollTestSetup(t *testing.T) {
	t.Helper()
	original := azureAsyncPollInterval
	azureAsyncPollInterval = time.Millisecond
	t.Cleanup(func() { azureAsyncPollInterval = original })
}

// The defect: the caller's `defer httpResp.Body.Close()` evaluated httpResp.Body
// at the defer statement, binding the FIRST response. The loop then reassigned
// httpResp, so the final response -- the one actually decoded -- was never closed.
// Azure answers 202 for any NIC on a running VM, so this leaked once per
// interface on the success path.
func TestPollAzureAsyncOperationClosesEveryIntermediateBody(t *testing.T) {
	pollTestSetup(t)

	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch hits.Add(1) {
		case 1, 2:
			// Two rounds of "still working", as a slow operation gives.
			w.Header().Set("Location", srv.URL+"/poll")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"InProgress"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()

	client, tracker := trackedClient(t)
	first, err := client.Post(srv.URL, "application/json", nil)
	require.NoError(t, err)

	final, err := pollAzureAsyncOperation(context.Background(), client, first, "token")
	require.NoError(t, err)
	require.NotNil(t, final)
	assert.Equal(t, http.StatusOK, final.StatusCode)

	closes := tracker.closes()
	require.Len(t, closes, 3, "two 202s then the result")
	assert.Equal(t, int32(1), closes[0], "the first 202 body must be closed")
	assert.Equal(t, int32(1), closes[1], "the second 202 body must be closed")
	assert.Equal(t, int32(0), closes[2], "the final body is handed back open for the caller to read")

	// The caller's deferred drainAndClose is what closes the last one.
	body, err := io.ReadAll(final.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"value":[]}`, string(body))
	drainAndClose(final.Body)
	assert.Equal(t, int32(1), tracker.closes()[2])
}

// A response that is already final must be returned untouched, still open.
func TestPollAzureAsyncOperationPassesThroughANonAcceptedResponse(t *testing.T) {
	pollTestSetup(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	client, tracker := trackedClient(t)
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)

	final, err := pollAzureAsyncOperation(context.Background(), client, resp, "token")
	require.NoError(t, err)
	assert.Same(t, resp, final)
	assert.Equal(t, []int32{0}, tracker.closes(), "nothing to close yet")
}

// Every error path must close the body it is abandoning. These leaked too: the
// caller's deferred close was bound to a body the loop had already closed.
func TestPollAzureAsyncOperationClosesTheBodyOnEveryErrorPath(t *testing.T) {
	t.Run("202 with no Location header", func(t *testing.T) {
		pollTestSetup(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"InProgress"}`))
		}))
		defer srv.Close()

		client, tracker := trackedClient(t)
		resp, err := client.Post(srv.URL, "application/json", nil)
		require.NoError(t, err)

		final, err := pollAzureAsyncOperation(context.Background(), client, resp, "token")
		require.Error(t, err)
		assert.Nil(t, final)
		assert.Contains(t, err.Error(), "without a Location header")
		assert.Equal(t, []int32{1}, tracker.closes())
	})

	t.Run("the context is cancelled mid-poll", func(t *testing.T) {
		pollTestSetup(t)
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", srv.URL+"/poll")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"InProgress"}`))
		}))
		defer srv.Close()

		client, tracker := trackedClient(t)
		resp, err := client.Post(srv.URL, "application/json", nil)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		final, err := pollAzureAsyncOperation(ctx, client, resp, "token")
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
		assert.Nil(t, final)
		assert.Equal(t, []int32{1}, tracker.closes(), "the abandoned body must still be closed")
	})

	t.Run("the poll request itself fails", func(t *testing.T) {
		pollTestSetup(t)
		// Point Location at a closed listener so the poll cannot connect.
		dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		deadURL := dead.URL
		dead.Close()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", deadURL+"/poll")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"InProgress"}`))
		}))
		defer srv.Close()

		client, tracker := trackedClient(t)
		resp, err := client.Post(srv.URL, "application/json", nil)
		require.NoError(t, err)

		final, err := pollAzureAsyncOperation(context.Background(), client, resp, "token")
		require.Error(t, err)
		assert.Nil(t, final)
		assert.Equal(t, []int32{1}, tracker.closes())
	})
}

// The poll carries the bearer token, or ARM answers 401 and the loop never ends.
func TestPollAzureAsyncOperationAuthenticatesEachPoll(t *testing.T) {
	pollTestSetup(t)

	var authHeaders []string
	var mu sync.Mutex
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			mu.Unlock()
		}
		if hits.Add(1) == 1 {
			w.Header().Set("Location", srv.URL+"/poll")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, _ := trackedClient(t)
	resp, err := client.Post(srv.URL, "application/json", nil)
	require.NoError(t, err)

	final, err := pollAzureAsyncOperation(context.Background(), client, resp, "secret-token")
	require.NoError(t, err)
	drainAndClose(final.Body)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, authHeaders, 1)
	assert.Equal(t, "Bearer secret-token", authHeaders[0])
}

func TestDrainAndCloseToleratesANilBody(t *testing.T) {
	assert.NotPanics(t, func() { drainAndClose(nil) })
}

// The Go semantics the leak rested on, pinned so the shape is not reintroduced:
// a deferred method call evaluates its receiver where the DEFER STATEMENT is, not
// where the function returns. `defer resp.Body.Close()` before a loop that
// reassigns resp therefore closes the response the loop started with and never
// the one it ended on -- which reads as correct and leaks every time.
func TestDeferBindsItsReceiverAtTheDeferStatement(t *testing.T) {
	firstClosed, lastClosed := &atomic.Int32{}, &atomic.Int32{}
	emptyBody := func(counter *atomic.Int32) countingBody {
		return countingBody{ReadCloser: io.NopCloser(http.NoBody), closed: counter}
	}

	func() {
		body := emptyBody(firstClosed)
		defer body.Close() // binds THIS body, not whatever body ends up being
		body = emptyBody(lastClosed)
		_ = body
	}()

	assert.Equal(t, int32(1), firstClosed.Load(), "the deferred close hit the original")
	assert.Equal(t, int32(0), lastClosed.Load(), "and never the reassignment: that is the leak")

	// Wrapping in a closure defers the evaluation instead, which is the other way
	// to write it correctly when the variable must be reassigned.
	reassignedClosed := &atomic.Int32{}
	func() {
		body := emptyBody(firstClosed)
		defer func() { body.Close() }()
		body = emptyBody(reassignedClosed)
		_ = body
	}()
	assert.Equal(t, int32(1), reassignedClosed.Load(), "the closure sees the latest value")
}
