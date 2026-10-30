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
	"testing"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseInfo(t *testing.T) {
	info := "# Server\r\nredis_version:7.4.0\r\nredis_mode:standalone\r\n\r\n# Clients\r\nconnected_clients:1\r\n"
	got := ParseInfo(info)
	if got["redis_version"] != "7.4.0" {
		t.Errorf("redis_version = %q, want 7.4.0", got["redis_version"])
	}
	if got["redis_mode"] != "standalone" {
		t.Errorf("redis_mode = %q, want standalone", got["redis_mode"])
	}
	if got["connected_clients"] != "1" {
		t.Errorf("connected_clients = %q, want 1", got["connected_clients"])
	}
	if _, ok := got["# Server"]; ok {
		t.Error("section headers should be skipped")
	}
}

// writeClientPair writes a self-signed client certificate and its key.
func writeClientPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "auditor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func newConn(t *testing.T, opts map[string]string) *RedisdbConnection {
	t.Helper()
	opts[OptionHost] = "127.0.0.1"
	c, err := NewRedisdbConnection(1, &inventory.Asset{}, &inventory.Config{Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTLSClientCertificate(t *testing.T) {
	certPath, keyPath := writeClientPair(t)
	c := newConn(t, map[string]string{OptionTLSCert: certPath, OptionTLSKey: keyPath})
	if !c.tls {
		t.Error("a client certificate must turn TLS on")
	}
	cfg, err := c.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("client certificates = %d, want 1", len(cfg.Certificates))
	}
}

func TestTLSClientCertificateErrors(t *testing.T) {
	certPath, keyPath := writeClientPair(t)
	for name, opts := range map[string]map[string]string{
		"cert without key": {OptionTLSCert: certPath},
		"key without cert": {OptionTLSKey: keyPath},
		"key as cert":      {OptionTLSCert: keyPath, OptionTLSKey: keyPath},
		"missing file":     {OptionTLSCert: filepath.Join(t.TempDir(), "nope.crt"), OptionTLSKey: keyPath},
	} {
		if _, err := newConn(t, opts).tlsConfig(); err == nil {
			t.Errorf("%s: tlsConfig succeeded", name)
		}
	}
}

func TestTLSWithoutClientCertificate(t *testing.T) {
	cfg, err := newConn(t, map[string]string{OptionTLS: "true"}).tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("client certificates = %d with none configured", len(cfg.Certificates))
	}
}
