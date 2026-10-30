// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"
	"testing"
)

func TestMapEncrypt(t *testing.T) {
	cases := map[string]string{
		"strict":    "strict",
		"mandatory": "true",
		"true":      "true",
		"":          "true",
		"optional":  "false",
		"false":     "false",
		"disable":   "disable",
		"disabled":  "disable",
		"STRICT":    "strict",
		"bogus":     "true",
	}
	for in, want := range cases {
		if got := mapEncrypt(in); got != want {
			t.Errorf("mapEncrypt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDSNDefaultInstance(t *testing.T) {
	c := &MssqlConnection{
		host: "sql.contoso.com", port: 1433, database: "master",
		user: "sa", password: "p@ss", auth: "sql", encrypt: "mandatory",
	}
	u, err := url.Parse(c.dsn())
	if err != nil {
		t.Fatalf("dsn did not parse: %v", err)
	}
	if u.Scheme != "sqlserver" {
		t.Errorf("scheme = %q, want sqlserver", u.Scheme)
	}
	if u.Host != "sql.contoso.com:1433" {
		t.Errorf("host = %q, want sql.contoso.com:1433", u.Host)
	}
	if u.Path != "" {
		t.Errorf("path = %q, want empty for default instance", u.Path)
	}
	q := u.Query()
	if q.Get("database") != "master" {
		t.Errorf("database = %q, want master", q.Get("database"))
	}
	if q.Get("encrypt") != "true" {
		t.Errorf("encrypt = %q, want true", q.Get("encrypt"))
	}
	if user := u.User.Username(); user != "sa" {
		t.Errorf("user = %q, want sa", user)
	}
	if pw, _ := u.User.Password(); pw != "p@ss" {
		t.Errorf("password not carried through")
	}
}

func TestDSNNamedInstance(t *testing.T) {
	c := &MssqlConnection{
		host: "host", port: 1433, instance: "SQL2022",
		user: "sa", auth: "sql", encrypt: "strict", trustCert: true,
	}
	u, err := url.Parse(c.dsn())
	if err != nil {
		t.Fatalf("dsn did not parse: %v", err)
	}
	// A named instance carries the instance in the path and omits the port.
	if u.Host != "host" {
		t.Errorf("host = %q, want host (no port for named instance)", u.Host)
	}
	if u.Path != "/SQL2022" {
		t.Errorf("path = %q, want /SQL2022", u.Path)
	}
	q := u.Query()
	if q.Get("encrypt") != "strict" {
		t.Errorf("encrypt = %q, want strict", q.Get("encrypt"))
	}
	if q.Get("TrustServerCertificate") != "true" {
		t.Errorf("TrustServerCertificate = %q, want true", q.Get("TrustServerCertificate"))
	}
}

func TestDSNAzureFedAuth(t *testing.T) {
	c := &MssqlConnection{
		host: "host", port: 1433, user: "audit@contoso.com", token: "tok",
		auth: "azure", encrypt: "mandatory",
	}
	u, err := url.Parse(c.dsn())
	if err != nil {
		t.Fatalf("dsn did not parse: %v", err)
	}
	if got := u.Query().Get("fedauth"); got != "ActiveDirectoryAccessToken" {
		t.Errorf("fedauth = %q, want ActiveDirectoryAccessToken", got)
	}
	if pw, _ := u.User.Password(); pw != "tok" {
		t.Errorf("token not carried as password")
	}
}

func TestInstanceID(t *testing.T) {
	def := &MssqlConnection{host: "h", port: 1433}
	if got := def.InstanceID(); got != "h:1433" {
		t.Errorf("InstanceID default = %q, want h:1433", got)
	}
	named := &MssqlConnection{host: "h", port: 1433, instance: "SQL2022"}
	if got := named.InstanceID(); got != "h:SQL2022" {
		t.Errorf("InstanceID named = %q, want h:SQL2022", got)
	}
}
