// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

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
