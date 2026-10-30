// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func newTestConn(t *testing.T, apiURL, org, key, secret string) (*ClickhousecloudConnection, error) {
	t.Helper()
	opts := map[string]string{}
	if org != "" {
		opts[OptionOrg] = org
	}
	if apiURL != "" {
		opts[OptionAPIURL] = apiURL
	}
	conf := &inventory.Config{
		Type:        "clickhousecloud",
		Options:     opts,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(key, secret)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	return NewClickhousecloudConnection(1, asset, conf)
}

func TestConnectionValidation(t *testing.T) {
	if _, err := newTestConn(t, "", "", "k", "s"); err == nil {
		t.Error("expected error when organization-id is missing")
	}
	if _, err := newTestConn(t, "", "org1", "", ""); err == nil {
		t.Error("expected error when API key is missing")
	}
	c, err := newTestConn(t, "", "org1", "k", "s")
	if err != nil {
		t.Fatalf("valid connection errored: %v", err)
	}
	if c.ServerID() != "org1" || c.OrgID() != "org1" {
		t.Errorf("ServerID/OrgID = %q/%q", c.ServerID(), c.OrgID())
	}
}

func TestGetUnwrapsEnvelopeWithBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "keyid" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/organizations/org1/services":
			_, _ = w.Write([]byte(`{"result":[{"id":"s1","name":"prod"}]}`))
		case "/organizations/org1/denied":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := newTestConn(t, srv.URL, "org1", "keyid", "secret")
	if err != nil {
		t.Fatalf("connection: %v", err)
	}

	var services []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.Get(c.Context(), "/services", &services); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(services) != 1 || services[0].ID != "s1" || services[0].Name != "prod" {
		t.Errorf("decoded services = %+v", services)
	}

	// A 403 becomes a PermissionError so callers can degrade to empty.
	var ignored []any
	err = c.Get(c.Context(), "/denied", &ignored)
	if !IsPermissionError(err) {
		t.Errorf("expected PermissionError for 403, got %v", err)
	}
}

func TestGetBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := newTestConn(t, srv.URL, "org1", "wrong", "wrong")
	var out []any
	if err := c.Get(c.Context(), "/services", &out); !IsPermissionError(err) {
		t.Errorf("expected PermissionError for 401, got %v", err)
	}
}
