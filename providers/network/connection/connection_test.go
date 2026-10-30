// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// A server that speaks only TLS 1.0 with an RSA-key-exchange CBC suite (Apache 2.2 /
// OpenSSL 0.9.8) is still readable through the connection's HTTP client: Go's
// defaults refuse both, which made http.get fail on such a server.
func TestClientReadsLegacyTLSOnlyServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.2.6 (Win32) mod_ssl/2.2.6 OpenSSL/0.9.8e")
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}
	srv.StartTLS()
	defer srv.Close()

	conn := NewHostConnection(1, &inventory.Asset{}, &inventory.Config{Insecure: true})
	resp, err := conn.Client(false).Get(srv.URL)
	if err != nil {
		t.Fatalf("GET over TLS 1.0 / RSA-CBC: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Server"); got != "Apache/2.2.6 (Win32) mod_ssl/2.2.6 OpenSSL/0.9.8e" {
		t.Errorf("Server = %q", got)
	}
}

// Certificates are still verified unless the user asked for --insecure.
func TestClientVerifiesCertificatesByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	conn := NewHostConnection(1, &inventory.Asset{}, &inventory.Config{})
	if resp, err := conn.Client(false).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("GET to a self-signed server succeeded without --insecure")
	}
}

func TestClientBoundsHeadersAndBody(t *testing.T) {
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.Header().Set("Content-Length", "10")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			defer srv.Close()
			defer close(release)
			conn := NewHostConnection(1, &inventory.Asset{}, &inventory.Config{})
			c := conn.Client(false)
			require.Greater(t, c.Timeout, time.Duration(0))
			require.LessOrEqual(t, c.Timeout, time.Minute)
			require.Greater(t, conn.transport.ResponseHeaderTimeout, time.Duration(0))
			c.Timeout = 30 * time.Millisecond
			if phase == "headers" {
				conn.transport.ResponseHeaderTimeout = 20 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() {
				resp, err := c.Get(srv.URL)
				if resp != nil {
					defer resp.Body.Close()
					_, err = io.ReadAll(resp.Body)
				}
				done <- err
			}()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("HTTP phase was not bounded")
			}
		})
	}
}
