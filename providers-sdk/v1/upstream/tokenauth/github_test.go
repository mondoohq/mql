// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tokenauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGitHubProvider() *GitHubTokenProvider {
	return &GitHubTokenProvider{
		attemptTimeout: 200 * time.Millisecond,
		maxAttempts:    3,
		baseBackoff:    5 * time.Millisecond,
	}
}

func setGitHubEnv(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "secret-bearer")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/token?api-version=2.0")
}

func TestGitHubTokenProvider_RetriesAfterTimeout(t *testing.T) {
	// Synthetic: first response is slower than the per-attempt timeout; no real target showed this.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		_, _ = w.Write([]byte(`{"value":"tok"}`))
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	got, err := newTestGitHubProvider().GetToken(context.Background(), "aud")
	require.NoError(t, err)
	assert.Equal(t, "tok", got)
	assert.Equal(t, int32(2), calls.Load())
}

func TestGitHubTokenProvider_RetriesOn503(t *testing.T) {
	// Synthetic: transient 503 followed by success; no real target showed this.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"value":"tok"}`))
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	got, err := newTestGitHubProvider().GetToken(context.Background(), "aud")
	require.NoError(t, err)
	assert.Equal(t, "tok", got)
	assert.Equal(t, int32(2), calls.Load())
}

func TestGitHubTokenProvider_NoRetryOnClientError(t *testing.T) {
	// Synthetic: 401 is not transient; no real target showed this.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	_, err := newTestGitHubProvider().GetToken(context.Background(), "aud")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Equal(t, int32(1), calls.Load())
}

func TestGitHubTokenProvider_PersistentServerError(t *testing.T) {
	// Synthetic: endpoint keeps failing with 500; no real target showed this.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	_, err := newTestGitHubProvider().GetToken(context.Background(), "aud")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 attempt(s)")
	assert.Contains(t, err.Error(), "500")
	assert.NotContains(t, err.Error(), "secret-bearer")
	assert.Equal(t, int32(3), calls.Load())
}

func TestGitHubTokenProvider_ContextCancelled(t *testing.T) {
	// Synthetic: the caller's deadline hits while waiting out a long Retry-After; no real target showed this.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := newTestGitHubProvider().GetToken(ctx, "aud")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestGitHubTokenProvider_ContextEndsDuringRequest(t *testing.T) {
	// Synthetic: the caller's deadline hits while a request is in flight; no real target showed this.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	p := newTestGitHubProvider()
	p.attemptTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.GetToken(ctx, "aud")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestGitHubTokenProvider_SendsAuthAndAudience(t *testing.T) {
	// Synthetic: request shape check against a local server.
	var gotAuth, gotAud, gotAPI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAud = r.URL.Query().Get("audience")
		gotAPI = r.URL.Query().Get("api-version")
		_, _ = w.Write([]byte(`{"value":"tok"}`))
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	// The audience is a URI; an unescaped "&" or "?" would split it.
	aud := "//iam.example.com/projects/p?pool=a&provider=b"
	_, err := newTestGitHubProvider().GetToken(context.Background(), aud)
	require.NoError(t, err)
	assert.Equal(t, "bearer secret-bearer", gotAuth)
	assert.Equal(t, aud, gotAud)
	assert.Equal(t, "2.0", gotAPI)
}

func TestCappedBackoff(t *testing.T) {
	// Synthetic: a huge Retry-After must not stall the caller; no real target showed this.
	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"3600"}},
	}
	assert.Equal(t, 30*time.Second, cappedBackoff(time.Second, 30*time.Second, 0, resp))

	// Synthetic: without Retry-After the exponential backoff applies.
	got := cappedBackoff(time.Second, 30*time.Second, 1, &http.Response{StatusCode: http.StatusServiceUnavailable})
	assert.Equal(t, 2*time.Second, got)
}

func TestGitHubTokenProvider_MissingEnv(t *testing.T) {
	// Synthetic: running outside GitHub Actions.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")

	_, err := (&GitHubTokenProvider{}).GetToken(context.Background(), "aud")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment variables not set")
}

func TestGitHubTokenProvider_EmptyValueIsError(t *testing.T) {
	// Synthetic: a 200 with an empty token must fail and not be retried; no real target showed this.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"value":""}`))
	}))
	defer srv.Close()
	setGitHubEnv(t, srv)

	_, err := newTestGitHubProvider().GetToken(context.Background(), "aud")
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}
