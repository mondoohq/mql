// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestDefaults(t *testing.T) {
	t.Setenv(EnvPassword, "")
	conn := testConn(t, "yb.example.com", nil)
	if conn.MasterEndpoint() != "yb.example.com:7000" || conn.TserverEndpoint() != "yb.example.com:9000" {
		t.Errorf("endpoints %q %q", conn.MasterEndpoint(), conn.TserverEndpoint())
	}
	u, err := url.Parse(conn.ysqlConnString())
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "yb.example.com:5433" || u.User.Username() != "yugabyte" || u.Path != "/yugabyte" {
		t.Errorf("connString = %s", u.Redacted())
	}
	if got := u.Query().Get("sslmode"); got != "prefer" {
		t.Errorf("sslmode = %q, want prefer", got)
	}
	if user, _ := conn.ycqlCredentials(); user != "cassandra" || conn.ycqlPort != 9042 || conn.ycqlTLS {
		t.Errorf("ycql user %q port %d tls %v", user, conn.ycqlPort, conn.ycqlTLS)
	}
	if conn.URL("h:7000", "/x") != "http://h:7000/x" {
		t.Errorf("URL = %q", conn.URL("h:7000", "/x"))
	}
}

func TestPortsUserAndCA(t *testing.T) {
	conf := &inventory.Config{Type: "yugabyte", Host: "127.0.0.1", Options: map[string]string{
		OptionMasterHTTPPort:  "17000",
		OptionTserverHTTPPort: "19000",
		OptionYSQLPort:        "15433",
		OptionYCQLPort:        "19042",
		OptionSSLRootCert:     "/certs/ca.crt",
		OptionHTTPS:           "true",
	}, Credentials: []*vault.Credential{vault.NewPasswordCredential("auditor", "pw")}}
	conn, err := NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatal(err)
	}
	if conn.MasterEndpoint() != "127.0.0.1:17000" || conn.TserverEndpoint() != "127.0.0.1:19000" || conn.ycqlPort != 19042 {
		t.Errorf("endpoints %q %q ycql %d", conn.MasterEndpoint(), conn.TserverEndpoint(), conn.ycqlPort)
	}
	u, _ := url.Parse(conn.ysqlConnString())
	if u.Host != "127.0.0.1:15433" || u.User.Username() != "auditor" {
		t.Errorf("connString = %s", u.Redacted())
	}
	// A CA means a cluster that encrypts client connections.
	if got := u.Query().Get("sslmode"); got != "verify-full" {
		t.Errorf("sslmode = %q, want verify-full", got)
	}
	if user, password := conn.ycqlCredentials(); !conn.ycqlTLS || user != "auditor" || password != "pw" {
		t.Errorf("ycql tls %v user %q", conn.ycqlTLS, user)
	}
	if conn.URL("h:7000", "/x") != "https://h:7000/x" {
		t.Errorf("URL = %q", conn.URL("h:7000", "/x"))
	}
}

func TestPasswordFromEnvironment(t *testing.T) {
	t.Setenv(EnvPassword, "from-env")
	conn := testConn(t, "h", nil)
	if conn.password != "from-env" {
		t.Error("password not read from the environment")
	}

	conf := &inventory.Config{Type: "yugabyte", Host: "h", Options: map[string]string{},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("u", "given")}}
	conn, err := NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatal(err)
	}
	if conn.password != "given" {
		t.Error("environment overrode a given password")
	}
}

func TestYCQLCredentials(t *testing.T) {
	t.Setenv(EnvPassword, "")
	t.Setenv(EnvYCQLPassword, "")
	conf := &inventory.Config{Type: "yugabyte", Host: "h", Options: map[string]string{},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("yugabyte", "ysql-pw"),
			vault.NewPasswordCredential("cassandra", "ycql-pw"),
		}}
	conn, err := NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ysqlUser() != "yugabyte" || conn.password != "ysql-pw" {
		t.Errorf("ysql user %q", conn.ysqlUser())
	}
	if user, password := conn.ycqlCredentials(); user != "cassandra" || password != "ycql-pw" {
		t.Errorf("ycql user %q", user)
	}

	// Only a YCQL password from the environment; the user stays shared.
	t.Setenv(EnvYCQLPassword, "env-ycql")
	conn = testConn(t, "h", nil)
	if user, password := conn.ycqlCredentials(); user != "cassandra" || password != "env-ycql" {
		t.Errorf("ycql user %q from env", user)
	}
}

func TestInvalidPortAndMissingHost(t *testing.T) {
	for _, port := range []string{"x", "0", "70000"} {
		conf := &inventory.Config{Type: "yugabyte", Host: "h", Options: map[string]string{OptionYSQLPort: port}}
		if _, err := NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf); err == nil {
			t.Errorf("port %q did not fail", port)
		}
	}
	conf := &inventory.Config{Type: "yugabyte", Options: map[string]string{}}
	if _, err := NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf); err == nil {
		t.Error("missing host did not fail")
	}
}

func TestTLSConfigModes(t *testing.T) {
	cases := []struct {
		opts           map[string]string
		skipVerify     bool
		chainOnlyCheck bool
	}{
		{map[string]string{}, false, false},
		{map[string]string{OptionSSLMode: "verify-full"}, false, false},
		{map[string]string{OptionSSLMode: "verify-ca"}, true, true},
		{map[string]string{OptionSSLMode: "require"}, true, false},
		{map[string]string{OptionTLSInsecure: "true"}, true, false},
	}
	for _, c := range cases {
		cfg, err := testConn(t, "h", c.opts).tlsConfig("h")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.InsecureSkipVerify != c.skipVerify || (cfg.VerifyPeerCertificate != nil) != c.chainOnlyCheck {
			t.Errorf("%v: skip %v chain-only %v", c.opts, cfg.InsecureSkipVerify, cfg.VerifyPeerCertificate != nil)
		}
	}
}

func TestVerifyChainRejectsEmpty(t *testing.T) {
	if err := verifyChain(nil)(nil, nil); err == nil {
		t.Error("no certificate accepted")
	}
}
