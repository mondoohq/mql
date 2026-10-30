// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func newTestConn(t *testing.T, opts map[string]string, user string) *CockroachdbConnection {
	t.Helper()
	conf := &inventory.Config{Type: "cockroachdb", Host: "crdb.example.com", Options: opts}
	if user != "" {
		conf.Credentials = []*vault.Credential{vault.NewPasswordCredential(user, "")}
	}
	conn, err := NewCockroachdbConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatalf("NewCockroachdbConnection: %v", err)
	}
	return conn
}

func TestDefaults(t *testing.T) {
	conn := newTestConn(t, nil, "")
	u, err := url.Parse(conn.connString())
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "crdb.example.com:26257" || u.User.Username() != "root" || u.Path != "/defaultdb" {
		t.Errorf("connString = %s, want root@crdb.example.com:26257/defaultdb", u.Redacted())
	}
	if got := u.Query().Get("sslmode"); got != "prefer" {
		t.Errorf("sslmode = %q, want prefer", got)
	}
}

func TestCertsDir(t *testing.T) {
	conn := newTestConn(t, map[string]string{OptionCertsDir: "/certs"}, "auditor")
	q, _ := url.Parse(conn.connString())
	for key, want := range map[string]string{
		"sslmode":     "verify-full",
		"sslrootcert": "/certs/ca.crt",
		"sslcert":     "/certs/client.auditor.crt",
		"sslkey":      "/certs/client.auditor.key",
	} {
		if got := q.Query().Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestCertsDirKeepsExplicitOptions(t *testing.T) {
	conn := newTestConn(t, map[string]string{
		OptionCertsDir:    "/certs",
		OptionSSLMode:     "verify-ca",
		OptionSSLRootCert: "/other/ca.pem",
	}, "")
	q, _ := url.Parse(conn.connString())
	if got := q.Query().Get("sslmode"); got != "verify-ca" {
		t.Errorf("sslmode = %q, want verify-ca", got)
	}
	if got := q.Query().Get("sslrootcert"); got != "/other/ca.pem" {
		t.Errorf("sslrootcert = %q, want /other/ca.pem", got)
	}
	if got := q.Query().Get("sslcert"); got != "/certs/client.root.crt" {
		t.Errorf("sslcert = %q, want /certs/client.root.crt", got)
	}
}

func TestInvalidPortAndMissingHost(t *testing.T) {
	conf := &inventory.Config{Type: "cockroachdb", Host: "h", Options: map[string]string{OptionPort: "x"}}
	if _, err := NewCockroachdbConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf); err == nil {
		t.Error("invalid port did not fail")
	}
	conf = &inventory.Config{Type: "cockroachdb", Options: map[string]string{}}
	if _, err := NewCockroachdbConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf); err == nil {
		t.Error("missing host did not fail")
	}
}
