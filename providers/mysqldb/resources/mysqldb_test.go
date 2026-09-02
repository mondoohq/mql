// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"strings"
	"testing"
)

func TestIsYes(t *testing.T) {
	for _, s := range []string{"YES", "Y", "ON", "1"} {
		if !isYes(s) {
			t.Errorf("isYes(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"NO", "N", "OFF", "0", ""} {
		if isYes(s) {
			t.Errorf("isYes(%q) = true, want false", s)
		}
	}
}

func TestGrantee(t *testing.T) {
	if got := grantee("appuser", "%"); got != "'appuser'@'%'" {
		t.Errorf("grantee = %q", got)
	}
	if got := grantee("", "localhost"); got != "''@'localhost'" {
		t.Errorf("anonymous grantee = %q", got)
	}
}

func TestIdentifierBuilders(t *testing.T) {
	if got := userResourceID("SRV", "root", "localhost"); got != "SRV/user/root@localhost" {
		t.Errorf("userResourceID = %q", got)
	}
	if got := schemaResourceID("SRV", "appdb"); got != "SRV/schema/appdb" {
		t.Errorf("schemaResourceID = %q", got)
	}
	// composite privilege id must vary by scope, object, and type
	a := privilegeResourceID("p", "GLOBAL", "", "", "SUPER")
	b := privilegeResourceID("p", "SCHEMA", "appdb", "", "SELECT")
	c := privilegeResourceID("p", "TABLE", "appdb", "t1", "SELECT")
	if a == b || b == c || a == c {
		t.Errorf("privilegeResourceID collides: %q %q %q", a, b, c)
	}
}

// The hasPassword field must be derived from a server-side emptiness test, so
// that mysql.user.authentication_string (the credential) never crosses the
// connection. These tests pin both halves of that: the SQL projection and the
// mapping of its result.

func TestHasPasswordExprDoesNotSelectTheCredential(t *testing.T) {
	for _, alias := range []string{"", "u."} {
		expr := hasPasswordExpr(alias)
		want := "LENGTH(COALESCE(" + alias + "authentication_string, '')) > 0"
		if expr != want {
			t.Errorf("hasPasswordExpr(%q) = %q, want %q", alias, expr, want)
		}
		// the column may only appear inside LENGTH(), never as a bare
		// projection that would transfer the hash itself
		if !strings.Contains(expr, "LENGTH(") {
			t.Errorf("hasPasswordExpr(%q) = %q, must project through LENGTH", alias, expr)
		}
	}
}

func TestUserColumnsNeverProjectsTheCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		alias   string
		mariadb bool
	}{
		{"mysql", "", false},
		{"mysql aliased", "u.", false},
		{"mariadb", "", true},
		{"mariadb aliased", "u.", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cols := userColumns(tc.alias, tc.mariadb)
			// every mention of the credential column must be wrapped in the
			// length comparison; a bare COALESCE(...) would ship the hash
			if strings.Contains(cols, "COALESCE("+tc.alias+"authentication_string, ''),") {
				t.Errorf("userColumns projects the raw credential: %s", cols)
			}
			if !strings.Contains(cols, hasPasswordExpr(tc.alias)) {
				t.Errorf("userColumns missing hasPassword projection: %s", cols)
			}
			if n := strings.Count(cols, "authentication_string"); n != 1 {
				t.Errorf("authentication_string appears %d times, want 1: %s", n, cols)
			}
		})
	}
}

// countSelectColumns counts comma-separated projections at parenthesis depth
// zero, so commas inside COALESCE() and LENGTH() do not inflate the count.
func countSelectColumns(list string) int {
	depth, n := 0, 1
	for _, r := range list {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				n++
			}
		}
	}
	return n
}

func TestUserColumnsCountMatchesScan(t *testing.T) {
	// the scan targets in scanMysqldbUser are positional, so replacing the
	// credential projection must keep the column count intact
	if got := countSelectColumns(userColumns("", false)); got != 11 {
		t.Errorf("mysql userColumns has %d columns, want 11", got)
	}
	if got := countSelectColumns(userColumns("u.", false)); got != 11 {
		t.Errorf("aliased mysql userColumns has %d columns, want 11", got)
	}
	if got := countSelectColumns(userColumns("", true)); got != 8 {
		t.Errorf("mariadb userColumns has %d columns, want 8", got)
	}
	if got := countSelectColumns(userColumns("u.", true)); got != 8 {
		t.Errorf("aliased mariadb userColumns has %d columns, want 8", got)
	}
}

func TestHasPasswordValue(t *testing.T) {
	cases := []struct {
		name string
		in   sql.NullInt64
		want bool
	}{
		// a hashing plugin with a credential set: caching_sha2_password,
		// mysql_native_password, ed25519 -> non-empty -> 1
		{"password set", sql.NullInt64{Int64: 1, Valid: true}, true},
		// CREATE USER with no IDENTIFIED BY, and the socket plugins
		// (auth_socket / unix_socket), both store an empty string -> 0
		{"no password", sql.NullInt64{Int64: 0, Valid: true}, false},
		// COALESCE rules this out, but a NULL must read as "no password"
		// rather than erroring or reporting a credential
		{"null", sql.NullInt64{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasPasswordValue(tc.in); got != tc.want {
				t.Errorf("hasPasswordValue(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
