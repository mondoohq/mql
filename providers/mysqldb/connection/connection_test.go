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
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mondoo.com/mql/llx"
)

func TestClassifyFlavor(t *testing.T) {
	cases := []struct {
		comment, version, want string
	}{
		{"MySQL Community Server - GPL", "8.0.40", "mysql"},
		{"mariadb.org binary distribution", "11.4.2-MariaDB", "mariadb"},
		{"MySQL Community Server (GPL)", "10.11.8-MariaDB-1:10.11.8+maria~ubu2204", "mariadb"},
		{"Percona Server (GPL), Release 30", "8.0.36-28", "percona"},
		{"", "8.4.0", "mysql"},
	}
	for _, tc := range cases {
		if got := classifyFlavor(tc.comment, tc.version); got != tc.want {
			t.Errorf("classifyFlavor(%q, %q) = %q, want %q", tc.comment, tc.version, got, tc.want)
		}
	}
}

func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
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

func TestTLSConfigFalseIgnoresCertificateFlags(t *testing.T) {
	// --tls-mode false with --tls-ca used TLS anyway
	for _, mode := range []string{"false", "0", "FALSE"} {
		c := &MysqldbConnection{tlsMode: mode, tlsCA: "/does/not/matter.pem", tlsCert: "c.pem", tlsKey: "k.pem"}
		cfg, fallback, err := c.tlsConfig()
		if err != nil || cfg != nil || fallback {
			t.Errorf("tls-mode %q = %v, %v, %v; want plaintext", mode, cfg, fallback, err)
		}
	}
}

func TestTLSConfigPreferred(t *testing.T) {
	c := &MysqldbConnection{tlsMode: "preferred"}
	cfg, fallback, err := c.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !fallback {
		t.Error("preferred must fall back to plaintext when the server has no TLS")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("preferred without a CA cannot verify the server")
	}
	if cfg.MinVersion != 0 || cfg.CipherSuites != nil {
		t.Errorf("preferred must keep Go's TLS defaults: min=%x suites=%v", cfg.MinVersion, cfg.CipherSuites)
	}

	// a CA with preferred verifies the server but still falls back to
	// plaintext against a server without TLS (it used to hard-fail)
	c = &MysqldbConnection{tlsMode: "preferred", tlsCA: writeTestCA(t), tlsServerName: "db.example.com"}
	cfg, fallback, err = c.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !fallback || cfg.InsecureSkipVerify || cfg.RootCAs == nil || cfg.ServerName != "db.example.com" {
		t.Errorf("preferred with CA = %+v fallback=%v", cfg, fallback)
	}
}

func TestTLSConfigRequiredModes(t *testing.T) {
	ca := writeTestCA(t)
	for _, tc := range []struct {
		mode   string
		verify bool
	}{
		{"true", true}, {"1", true}, {"skip-verify", false},
	} {
		c := &MysqldbConnection{tlsMode: tc.mode, tlsCA: ca, tlsServerName: "10.0.0.5"}
		cfg, fallback, err := c.tlsConfig()
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if fallback {
			t.Errorf("%s must not fall back to plaintext", tc.mode)
		}
		if cfg.InsecureSkipVerify == tc.verify {
			t.Errorf("%s: InsecureSkipVerify = %v", tc.mode, cfg.InsecureSkipVerify)
		}
		if tc.verify && (cfg.RootCAs == nil || cfg.ServerName != "10.0.0.5") {
			t.Errorf("%s: CA or server name not applied: %+v", tc.mode, cfg)
		}
		if cfg.MinVersion != 0 {
			t.Errorf("%s: required modes keep Go's minimum TLS version, got %x", tc.mode, cfg.MinVersion)
		}
	}
}

func TestTLSConfigRejectsBadInput(t *testing.T) {
	if _, _, err := (&MysqldbConnection{tlsMode: "maybe"}).tlsConfig(); err == nil {
		t.Error("an unknown tls-mode must be rejected")
	}
	if _, _, err := (&MysqldbConnection{tlsMode: "true", tlsCert: "c.pem"}).tlsConfig(); err == nil {
		t.Error("tls-cert without tls-key must be rejected")
	}
}

func TestDriverConfigTimeouts(t *testing.T) {
	c := &MysqldbConnection{tlsMode: "false", host: "192.0.2.1", port: 3306, user: "u"}
	cfg, err := c.driverConfig()
	if err != nil {
		t.Fatal(err)
	}
	// a blackholed host took 129 s to fail without a dial timeout
	if cfg.Timeout <= 0 || cfg.Timeout > 30*time.Second {
		t.Errorf("dial timeout = %v", cfg.Timeout)
	}
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 {
		t.Errorf("io timeouts = %v / %v", cfg.ReadTimeout, cfg.WriteTimeout)
	}
}

func TestClassifyConnectError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want llx.ErrorKind
	}{
		{"wrong password", &mysqldriver.MySQLError{Number: 1045, Message: "Access denied for user 'mqlsu'@'127.0.0.1' (using password: YES)"}, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"account locked", &mysqldriver.MySQLError{Number: 3118, Message: "Access denied for user 'mqllocked'@'localhost'. Account is locked."}, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"password expired", &mysqldriver.MySQLError{Number: 1862, Message: "Your password has expired."}, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"insecure transport", &mysqldriver.MySQLError{Number: 3159, Message: "Connections using insecure transport are prohibited while --require_secure_transport=ON."}, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"timeout", &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		// not a statement about the server's availability or the caller
		{"dns", &net.DNSError{Err: "no such host", Name: "db.invalid", IsNotFound: true}, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"syntax", &mysqldriver.MySQLError{Number: 1064, Message: "syntax"}, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tc := range cases {
		err := classifyConnectError(tc.err)
		if got := llx.KindOf(err); got != tc.want {
			t.Errorf("%s: kind = %v, want %v", tc.name, got, tc.want)
		}
		if !errors.Is(err, tc.err) && err != tc.err {
			t.Errorf("%s: original error lost: %v", tc.name, err)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
