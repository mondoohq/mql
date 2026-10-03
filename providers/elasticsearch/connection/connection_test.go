// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func newTestConn(t *testing.T, opts map[string]string) *ElasticsearchConnection {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	if opts[OptionHost] == "" {
		opts[OptionHost] = "es.example.com"
	}
	conf := &inventory.Config{Type: "elasticsearch", Options: opts}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := NewElasticsearchConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("NewElasticsearchConnection: %v", err)
	}
	return conn
}

func TestAddressDefaults(t *testing.T) {
	// Default scheme https and port 9200.
	if got := newTestConn(t, nil).address(); got != "https://es.example.com:9200" {
		t.Errorf("address = %q", got)
	}
	c := newTestConn(t, map[string]string{OptionScheme: "http", OptionPort: "9201"})
	if got := c.address(); got != "http://es.example.com:9201" {
		t.Errorf("address = %q", got)
	}
}

func TestTransportDisabledForPlainHTTP(t *testing.T) {
	// http with no TLS material needs no custom transport.
	c := newTestConn(t, map[string]string{OptionScheme: "http"})
	tr, err := c.transport()
	if err != nil {
		t.Fatal(err)
	}
	if tr != nil {
		t.Error("plain http should not build a custom transport")
	}
}

func TestTransportInsecure(t *testing.T) {
	c := newTestConn(t, map[string]string{OptionScheme: "https", OptionTLSInsecure: "true"})
	tr, err := c.transport()
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil || tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected an insecure TLS transport")
	}
}

func TestTransportBadCAErrors(t *testing.T) {
	c := newTestConn(t, map[string]string{OptionScheme: "https", OptionTLSCA: "/no/such/ca.pem"})
	if _, err := c.transport(); err == nil {
		t.Error("expected an error for a missing CA file")
	}
}

func TestPermissionError(t *testing.T) {
	err := &PermissionError{Path: "/_security/user", StatusCode: 403}
	if !IsPermissionError(err) {
		t.Error("PermissionError should be classified as a permission error")
	}
	if IsPermissionError(errors.New("boom")) {
		t.Error("a plain error is not a permission error")
	}
	if IsPermissionError(nil) {
		t.Error("nil is not a permission error")
	}
}

// The body Elasticsearch 8.19 returned live to a user holding only the
// monitor cluster privilege.
const monuserUserGet403 = `{"error":{"root_cause":[{"type":"security_exception","reason":"action [cluster:admin/xpack/security/user/get] is unauthorized for user [monuser] with effective roles [monitor_only], this action is granted by the cluster privileges [read_security,manage_security,all]"}],"type":"security_exception","reason":"action [cluster:admin/xpack/security/user/get] is unauthorized for user [monuser] with effective roles [monitor_only], this action is granted by the cluster privileges [read_security,manage_security,all]"},"status":403}`

func TestGetRefusalKeepsStatusAndReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		switch r.URL.Path {
		case "/_security/user":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, monuserUserGet403)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"type":"security_exception","reason":"missing authentication credentials for REST request [/]"},"status":401}`)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := newTestConn(t, map[string]string{OptionHost: u.Hostname(), OptionPort: u.Port(), OptionScheme: "http"})

	err := c.Get("/_security/user", nil)
	var pe *PermissionError
	if !errors.As(err, &pe) {
		t.Fatalf("Get = %v, want a PermissionError", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", pe.StatusCode)
	}
	if !strings.Contains(pe.Reason, "granted by the cluster privileges [read_security,manage_security,all]") {
		t.Errorf("Reason = %q, want the cluster's explanation", pe.Reason)
	}
	if !strings.Contains(err.Error(), "read_security") {
		t.Errorf("Error() = %q drops the reason", err.Error())
	}

	err = c.Get("/", nil)
	if !errors.As(err, &pe) || pe.StatusCode != http.StatusUnauthorized {
		t.Errorf("Get(/) = %v, want a 401 PermissionError", err)
	}
	// a wrapped PermissionError is still one
	if !IsPermissionError(fmt.Errorf("users: %w", err)) {
		t.Error("IsPermissionError misses a wrapped PermissionError")
	}
}

func TestErrorReasonIgnoresOtherBodies(t *testing.T) {
	for _, body := range []string{"", "not json", `{"status":403}`, `<html>Forbidden</html>`} {
		if got := errorReason([]byte(body)); got != "" {
			t.Errorf("errorReason(%q) = %q, want empty", body, got)
		}
	}
}
