// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServerConn points a connection at a local test server over plain HTTP,
// with basic-auth credentials the server can check.
func newServerConn(t *testing.T, handler http.HandlerFunc) *OpensearchConnection {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	conn := newTestConn(t, map[string]string{
		OptionHost:   host,
		OptionPort:   port,
		OptionScheme: "http",
	})
	conn.user = "auditor"
	conn.password = "secret"
	return conn
}

func TestGetDecodesBody(t *testing.T) {
	var gotPath, gotUser, gotPass string
	conn := newServerConn(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cluster_name":"prod","status":"green"}`))
	})

	var out struct {
		ClusterName string `json:"cluster_name"`
		Status      string `json:"status"`
	}
	if err := conn.Get("/_cluster/health", &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotPath != "/_cluster/health" {
		t.Errorf("path = %q", gotPath)
	}
	if gotUser != "auditor" || gotPass != "secret" {
		t.Errorf("basic auth = %q/%q", gotUser, gotPass)
	}
	if out.ClusterName != "prod" || out.Status != "green" {
		t.Errorf("decoded = %+v", out)
	}
}

func TestGetClassifiesDeniedAsPermissionError(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		conn := newServerConn(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		})
		err := conn.Get("/_plugins/_security/api/roles", nil)
		if !IsPermissionError(err) {
			t.Errorf("status %d: err = %v, want a permission error", code, err)
		}
	}
}

func TestGetReportsOtherStatusAsError(t *testing.T) {
	conn := newServerConn(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no such index"}`))
	})
	err := conn.Get("/missing/_settings", nil)
	if err == nil {
		t.Fatal("Get succeeded on a 404")
	}
	if IsPermissionError(err) {
		t.Error("a 404 is not a permission error")
	}
	if !strings.Contains(err.Error(), "status 404") || !strings.Contains(err.Error(), "no such index") {
		t.Errorf("err = %v", err)
	}
}
