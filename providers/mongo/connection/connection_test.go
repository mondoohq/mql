// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// newTestConn builds a connection from options, always supplying a host so the
// constructor succeeds.
func newTestConn(t *testing.T, opts map[string]string) *MongoConnection {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	if opts[OptionHost] == "" {
		opts[OptionHost] = "db.example.com"
	}
	conf := &inventory.Config{Type: "mongo", Options: opts}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := NewMongoConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("NewMongoConnection: %v", err)
	}
	return conn
}

// writeTestCA generates a self-signed CA and writes it as PEM, returning the path.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTLSConfigDisabled(t *testing.T) {
	conn := newTestConn(t, nil)
	cfg, err := conn.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Errorf("expected nil tls config when TLS is off, got %+v", cfg)
	}
}

func TestTLSConfigCAImpliesTLSAndPopulatesRoots(t *testing.T) {
	caPath := writeTestCA(t)
	// No explicit --tls: a CA path alone must enable TLS.
	conn := newTestConn(t, map[string]string{OptionTLSCA: caPath})
	if !conn.tls {
		t.Error("a --tls-ca path should imply TLS")
	}
	cfg, err := conn.tlsConfig()
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected RootCAs to be populated from the CA file")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false without --tls-insecure")
	}
}

func TestTLSConfigInsecure(t *testing.T) {
	conn := newTestConn(t, map[string]string{OptionTLSInsecure: "true"})
	if !conn.tls {
		t.Error("--tls-insecure should imply TLS")
	}
	cfg, err := conn.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || !cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestTLSConfigBadCAErrors(t *testing.T) {
	// A missing file must surface an error, not be silently ignored.
	conn := newTestConn(t, map[string]string{OptionTLSCA: filepath.Join(t.TempDir(), "nope.pem")})
	if _, err := conn.tlsConfig(); err == nil {
		t.Error("expected an error for a missing CA file")
	}

	// A file with no PEM certificates must also error.
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn2 := newTestConn(t, map[string]string{OptionTLSCA: garbage})
	if _, err := conn2.tlsConfig(); err == nil {
		t.Error("expected an error for a CA file with no certificates")
	}
}

// TestURIExcludesTLSParams guards that TLS is configured via SetTLSConfig, not
// URI query parameters (so the CA path is honored rather than silently dropped).
func TestURIExcludesTLSParams(t *testing.T) {
	conn := newTestConn(t, map[string]string{
		OptionTLS:         "true",
		OptionTLSInsecure: "true",
		OptionPort:        "27018",
	})
	uri := conn.uri()
	if strings.Contains(uri, "tls") || strings.Contains(uri, "ssl") {
		t.Errorf("uri should not carry TLS query params, got %q", uri)
	}
	if !strings.Contains(uri, "27018") {
		t.Errorf("uri should carry the configured port, got %q", uri)
	}
}

func TestPortDefaultAndOverride(t *testing.T) {
	if p := newTestConn(t, nil).Port(); p != 27017 {
		t.Errorf("default port = %d, want 27017", p)
	}
	if p := newTestConn(t, map[string]string{OptionPort: "27018"}).Port(); p != 27018 {
		t.Errorf("port = %d, want 27018", p)
	}
}

// A bare host is one server and must be audited as that server, not as the
// primary of the replica set it belongs to.
func TestClientOptionsDirectForBareHost(t *testing.T) {
	opts, err := newTestConn(t, map[string]string{OptionHost: "127.0.0.1", OptionPort: "28002"}).clientOptions()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Direct == nil || !*opts.Direct {
		t.Errorf("a bare host must use a direct connection, got %v", opts.Direct)
	}
	if len(opts.Hosts) != 1 || opts.Hosts[0] != "127.0.0.1:28002" {
		t.Errorf("hosts = %v", opts.Hosts)
	}
}

// A connection string keeps the topology it asks for.
func TestClientOptionsConnectionStringKeepsTopology(t *testing.T) {
	opts, err := newTestConn(t, map[string]string{OptionHost: "mongodb://a.example.com,b.example.com/?replicaSet=rs0"}).clientOptions()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Direct != nil && *opts.Direct {
		t.Error("a replica-set connection string must not be forced direct")
	}
	if opts.ReplicaSet == nil || *opts.ReplicaSet != "rs0" {
		t.Errorf("replicaSet = %v", opts.ReplicaSet)
	}
}
