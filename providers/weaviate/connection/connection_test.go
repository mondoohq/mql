// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestHTTPClientBounded(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		c := &WeaviateConnection{scheme: scheme, tlsInsecure: true}
		client, err := c.httpClient()
		require.NoError(t, err)
		require.Greater(t, client.Timeout, time.Duration(0))
		require.LessOrEqual(t, client.Timeout, time.Minute)
	}
}
func TestProbeAnonymousAccess(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   bool
		fail   bool
	}{{200, true, false}, {204, true, false}, {401, false, false}, {403, false, false}, {500, false, true}, {404, false, true}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Empty(t, r.Header.Get("Authorization"))
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			got, err := probeAnonymousAccess(t.Context(), srv.Client(), srv.URL)
			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, got)
		})
	}
}
func TestProbeAnonymousAccessCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		enabled, err := probeAnonymousAccess(ctx, srv.Client(), srv.URL)
		if enabled {
			t.Error("incomplete probe enabled anonymous access")
		}
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("anonymous probe ignored cancellation")
	}
}

func TestClientAPIKeyWithBoundedTransport(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version":"1.38.9"}`))
			}))
			if secure {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()
			u, err := url.Parse(srv.URL)
			require.NoError(t, err)
			host, port, err := net.SplitHostPort(u.Host)
			require.NoError(t, err)
			n, err := strconv.Atoi(port)
			require.NoError(t, err)
			c := &WeaviateConnection{host: host, port: n, scheme: u.Scheme, tlsInsecure: secure, apiKey: "test-token"}
			client, err := c.Client()
			require.NoError(t, err)
			meta, err := client.Misc().MetaGetter().Do(t.Context())
			require.NoError(t, err)
			require.Equal(t, "1.38.9", meta.Version)
		})
	}
}

type probeRoundTripper func(*http.Request) (*http.Response, error)

func (f probeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHTTPClientWithCustomDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = probeRoundTripper(func(r *http.Request) (*http.Response, error) { return nil, context.Canceled })
	defer func() { http.DefaultTransport = original }()
	client, err := (&WeaviateConnection{scheme: "https", tlsInsecure: true}).httpClient()
	require.NoError(t, err)
	require.Positive(t, client.Timeout)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.Proxy)
	require.NotNil(t, transport.DialContext)
	require.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
	require.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestHTTPClientPreservesDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	defaults := &http.Transport{ResponseHeaderTimeout: 7 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	http.DefaultTransport = defaults
	defer func() { http.DefaultTransport = original }()
	client, err := (&WeaviateConnection{scheme: "https", tlsInsecure: true}).httpClient()
	require.NoError(t, err)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotSame(t, defaults, transport)
	require.Equal(t, 7*time.Second, transport.ResponseHeaderTimeout)
	require.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	require.False(t, defaults.TLSClientConfig.InsecureSkipVerify, "connection TLS settings must not mutate the shared transport")
	require.Equal(t, uint16(tls.VersionTLS12), defaults.TLSClientConfig.MinVersion)
}

func TestHTTPClientPreservesCustomRoundTripperWithoutTLSOverrides(t *testing.T) {
	original := http.DefaultTransport
	called := false
	http.DefaultTransport = probeRoundTripper(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, context.Canceled
	})
	defer func() { http.DefaultTransport = original }()
	for _, scheme := range []string{"http", "https"} {
		client, err := (&WeaviateConnection{scheme: scheme}).httpClient()
		require.NoError(t, err)
		called = false
		_, err = client.Get(scheme + "://example.invalid/v1/meta")
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, called, "without TLS overrides, preserve the embedder's RoundTripper")
	}
}
