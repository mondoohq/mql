// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "testing"

// Rows below were read live from information_schema.USER_PRIVILEGES on MySQL
// 8.4 and MariaDB 11.8 as each scanner account.

func TestParseCurrentUser(t *testing.T) {
	cases := map[string]string{
		"mqlmid@%":            "'mqlmid'@'%'",
		"root@localhost":      "'root'@'localhost'",
		"app@corp@10.0.0.%":   "'app@corp'@'10.0.0.%'",
		"@localhost":          "''@'localhost'",
		"mqlapp@10.0.0.1":     "'mqlapp'@'10.0.0.1'",
		"user-without-a-host": "'user-without-a-host'@''",
	}
	for in, want := range cases {
		if got := parseCurrentUser(in); got != want {
			t.Errorf("parseCurrentUser(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCallerAccessFilteredView(t *testing.T) {
	// PROCESS, REPLICATION CLIENT and SELECT ON mysql.user: the view shows
	// the caller's own rows only
	a := newCallerAccess("mqlmid@%", []grantRow{
		{"'mqlmid'@'%'", "PROCESS"},
		{"'mqlmid'@'%'", "REPLICATION CLIENT"},
	})
	if a.GrantsVisible {
		t.Error("GrantsVisible = true for a view filtered to the caller")
	}
	if a.CanListSchemas() || a.CanListTables() || a.CanListRoutines() {
		t.Errorf("catalog listing allowed without global SELECT: %+v", a.Global)
	}
	if a.Self != "'mqlmid'@'%'" {
		t.Errorf("Self = %q", a.Self)
	}

	// USAGE only
	a = newCallerAccess("mqlnone@%", []grantRow{{"'mqlnone'@'%'", "USAGE"}})
	if a.GrantsVisible || a.CanListSchemas() || a.CanListTables() || a.CanListRoutines() {
		t.Errorf("USAGE-only account reported visibility: %+v", a)
	}
}

func TestCallerAccessUnfilteredView(t *testing.T) {
	// SELECT, PROCESS, REPLICATION CLIENT ON *.*: every account is listed
	a := newCallerAccess("mqlmon@%", []grantRow{
		{"'mariadb.sys'@'localhost'", "USAGE"},
		{"'mqlapp'@'10.0.0.1'", "PROCESS"},
		{"'mqlapp'@'10.0.0.1'", "FILE"},
		{"'mqlmon'@'%'", "SELECT"},
		{"'mqlmon'@'%'", "PROCESS"},
		{"'mqlmon'@'%'", "BINLOG MONITOR"},
		{"'root'@'localhost'", "SHOW DATABASES"},
	})
	if !a.GrantsVisible {
		t.Error("GrantsVisible = false with several grantees listed")
	}
	if !a.CanListSchemas() || !a.CanListTables() || !a.CanListRoutines() {
		t.Errorf("global SELECT did not allow catalog listing: %+v", a.Global)
	}
	// another account's privileges must not count as the caller's
	if a.Global["FILE"] || a.Global["SHOW DATABASES"] {
		t.Errorf("caller credited with another grantee's privileges: %+v", a.Global)
	}
}

func TestCallerAccessNarrowGlobals(t *testing.T) {
	a := newCallerAccess("aud@%", []grantRow{{"'aud'@'%'", "SHOW DATABASES"}})
	if !a.CanListSchemas() {
		t.Error("SHOW DATABASES must allow listing schemas")
	}
	if a.CanListTables() || a.CanListRoutines() {
		t.Error("SHOW DATABASES alone must not allow listing tables or routines")
	}
	a = newCallerAccess("aud@%", []grantRow{{"'aud'@'%'", "SHOW_ROUTINE"}})
	if !a.CanListRoutines() || a.CanListTables() {
		t.Errorf("SHOW_ROUTINE: routines=%v tables=%v", a.CanListRoutines(), a.CanListTables())
	}
}

func TestMajorVersion(t *testing.T) {
	cases := map[string]int{
		"8.0.46-37":                        8,
		"5.7.34-log":                       5,
		"8.4.11":                           8,
		"9.7.2":                            9,
		"26.7.0":                           26,
		"10.3.39-MariaDB-0ubuntu0.20.04.2": 10,
		"":                                 0,
	}
	for in, want := range cases {
		if got := majorVersion(in); got != want {
			t.Errorf("majorVersion(%q) = %d, want %d", in, got, want)
		}
	}
}
