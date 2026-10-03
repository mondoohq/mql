// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"
	"testing"
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

func TestTLSParamKeyword(t *testing.T) {
	for _, mode := range []string{"false", "skip-verify", "preferred", "true"} {
		c := &MysqldbConnection{tlsMode: mode}
		got, err := c.tlsParam()
		if err != nil {
			t.Fatalf("tlsParam(%q) error: %v", mode, err)
		}
		if got != mode {
			t.Errorf("tlsParam(%q) = %q, want passthrough", mode, got)
		}
	}
}

func TestDerivedServerID(t *testing.T) {
	// two MariaDB servers both reached as 127.0.0.1:3306 on different hosts
	a := derivedServerID("ip-10-0-1-5", "3306", "1", "/var/lib/mysql/")
	b := derivedServerID("ip-10-0-1-6", "3306", "1", "/var/lib/mysql/")
	if a == b {
		t.Errorf("servers on different hosts share id %q", a)
	}
	// two instances on one host
	c := derivedServerID("ip-10-0-1-5", "3307", "2", "/var/lib/mysql2/")
	if a == c {
		t.Errorf("instances on one host share id %q", a)
	}
	// the id must not depend on the name the server was reached by, and is
	// used as a platform id segment, so it must not carry a path separator
	if again := derivedServerID("ip-10-0-1-5", "3306", "1", "/var/lib/mysql/"); again != a {
		t.Errorf("id not stable: %q vs %q", a, again)
	}
	if strings.ContainsAny(a, "/:") || len(a) != 32 {
		t.Errorf("id %q is not a 32-character hex segment", a)
	}
}
