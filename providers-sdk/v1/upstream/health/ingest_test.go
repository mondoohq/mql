// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIngestReachable_AnyHttpStatusIsReachable(t *testing.T) {
	// The real endpoint answers 404 to anything that is not a presigned upload,
	// so a 404 is the healthy answer and 503 still proves the network path.
	for _, code := range []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(code)
		}))

		status := CheckIngestReachable(context.Background(), srv.Client(), srv.URL)
		srv.Close()

		assert.True(t, status.Reachable, "HTTP %d must count as reachable", code)
		assert.Equal(t, code, status.StatusCode)
		assert.Equal(t, srv.URL, status.Endpoint)
		assert.Empty(t, status.Reason)
		assert.Empty(t, status.Error)
	}
}

func TestCheckIngestReachable_SendsNoCredentials(t *testing.T) {
	var authorization, cookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		cookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	status := CheckIngestReachable(context.Background(), srv.Client(), srv.URL)

	require.True(t, status.Reachable)
	assert.Empty(t, authorization, "the probe must not authenticate")
	assert.Empty(t, cookie)
}

func TestCheckIngestReachable_EmptyEndpointSkipsTheNetwork(t *testing.T) {
	// A caller that could not derive an endpoint gets a zero value, not a
	// failure: nothing was checked, so nothing is wrong.
	status := CheckIngestReachable(context.Background(), http.DefaultClient, "")

	assert.False(t, status.Reachable)
	assert.Empty(t, status.Endpoint)
	assert.Empty(t, status.Reason)
	assert.Zero(t, status.LatencyMs)
}

func TestCheckIngestReachable_ConnectionRefused(t *testing.T) {
	// A listener that is closed before the probe runs gives a port nothing is
	// listening on, which is the reject-rather-than-drop firewall shape.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint := "http://" + listener.Addr().String()
	require.NoError(t, listener.Close())

	status := CheckIngestReachable(context.Background(), http.DefaultClient, endpoint)

	assert.False(t, status.Reachable)
	assert.Equal(t, IngestFailureConnectionRefused, status.Reason)
	assert.NotEmpty(t, status.Error)
	assert.Zero(t, status.StatusCode)
}

func TestCheckIngestReachable_TimeoutReportsLatency(t *testing.T) {
	// A handler that never answers stands in for a blackholing firewall. The
	// deadline comes from the caller's context, which is tighter than the
	// probe's own timeout, so the test does not wait it out.
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
	}))
	defer func() {
		close(blocked)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	status := CheckIngestReachable(ctx, srv.Client(), srv.URL)

	assert.False(t, status.Reachable)
	assert.Equal(t, IngestFailureTimeout, status.Reason)
	assert.NotEmpty(t, status.Error)
	// Latency is recorded on the failure path too — it is what tells a dropped
	// connection (waited out the deadline) from a rejected one (immediate).
	assert.GreaterOrEqual(t, status.LatencyMs, int64(40))
}

func TestCheckIngestReachable_MalformedEndpoint(t *testing.T) {
	status := CheckIngestReachable(context.Background(), http.DefaultClient, "https://ingest.us.mondoo.com/\x7f")

	assert.False(t, status.Reachable)
	assert.Equal(t, IngestFailureRequest, status.Reason)
	assert.NotEmpty(t, status.Error)
}

func TestCheckIngestReachable_NilClientIsUsable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	status := CheckIngestReachable(context.Background(), nil, srv.URL)

	assert.True(t, status.Reachable)
	assert.Equal(t, http.StatusNotFound, status.StatusCode)
}

func TestClassifyIngestFailure(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil", nil, ""},
		{
			// Wrapped the way http.Client returns it, to prove the classifier
			// walks the error tree instead of matching on the top-level type.
			name:     "dns",
			err:      &url.Error{Op: "Get", URL: "https://ingest.us.mondoo.com", Err: &net.DNSError{Err: "no such host", Name: "ingest.us.mondoo.com"}},
			expected: IngestFailureDNS,
		},
		{"tls verification", &tls.CertificateVerificationError{}, IngestFailureTLS},
		{"tls record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, IngestFailureTLS},
		{"connection refused", &url.Error{Op: "Get", Err: syscall.ECONNREFUSED}, IngestFailureConnectionRefused},
		{"connection reset", &url.Error{Op: "Get", Err: syscall.ECONNRESET}, IngestFailureConnectionReset},
		{"deadline exceeded", &url.Error{Op: "Get", Err: context.DeadlineExceeded}, IngestFailureTimeout},
		{"canceled", &url.Error{Op: "Get", Err: context.Canceled}, IngestFailureTimeout},
		{"net timeout", &url.Error{Op: "Get", Err: timeoutError{}}, IngestFailureTimeout},
		{"unrecognised", errors.New("boom"), IngestFailureOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, classifyIngestFailure(tt.err))
		})
	}
}

// timeoutError is a net.Error that reports a timeout without being one of the
// standard-library error values the classifier checks by identity.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
