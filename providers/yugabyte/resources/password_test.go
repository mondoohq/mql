// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// Measured: pg_authid.rolpassword on yugabytedb/yugabyte:2025.2.8.1-b8,
// 2026-11-13, for throwaway roles created for the test: app with password
// "app" (SCRAM-SHA-256, the default), reporter with "not-the-name", and
// legacy with "legacy" set under password_encryption = md5.
const (
	scramApp      = "SCRAM-SHA-256$4096:1Z1VHKdgHvmzpVpm/YVsAg==$9o2X28lihRl7JMfX1a5En1VB25MBSWeaeXOlgMRo7ww=:LohgT47yiazjPYSA1F3TqAmGPg5woGRLPyP62/w3JSo="
	scramReporter = "SCRAM-SHA-256$4096:eMFFC5nrZ1lAUwuo/IkOEg==$uATeGoxQweVJT05+cKDSheN8rvnPfgA6S42yH9c/GeY=:Gv2JDkogspdqe0raj1HWHiwmtTIkCTkIk5+hB8ahzp8="
	md5Legacy     = "md53e52083252dffea91cf4b0d6839aca98"
)

// Measured: system_auth.roles.salted_hash of the default cassandra role
// (password "cassandra") on the same image, with the NUL padding YCQL
// returns.
const bcryptCassandra = "$2a$12$DnMK2bimBpP48RK.Jh53uOXmMxsOHjqDogXYmjdDZ76/a1MDCYNC6\x00\x00\x00\x00"

func TestYSQLPasswordMatches(t *testing.T) {
	cases := []struct {
		hash, role, password string
		want                 bool
	}{
		{scramApp, "app", "app", true},
		{scramApp, "app", "App", false},
		{scramReporter, "reporter", "reporter", false},
		{scramReporter, "reporter", "not-the-name", true},
		{md5Legacy, "legacy", "legacy", true},
		// md5 salts with the role name: the same hash under another name fails.
		{md5Legacy, "other", "legacy", false},
		// Synthetic: no password, plain text, and malformed verifiers.
		{"", "app", "app", false},
		{"app", "app", "app", false},
		{"SCRAM-SHA-256$4096:notbase64$x:y", "app", "app", false},
		{"SCRAM-SHA-256$99999999:1Z1VHKdgHvmzpVpm/YVsAg==$9o2X28lihRl7JMfX1a5En1VB25MBSWeaeXOlgMRo7ww=:x", "app", "app", false},
		{"SCRAM-SHA-256$4096:1Z1VHKdgHvmzpVpm/YVsAg==", "app", "app", false},
	}
	for _, c := range cases {
		if got := ysqlPasswordMatches(c.hash, c.role, c.password); got != c.want {
			t.Errorf("ysqlPasswordMatches(%.24q, %q, %q) = %v, want %v", c.hash, c.role, c.password, got, c.want)
		}
	}
}

func TestYCQLPasswordMatches(t *testing.T) {
	if !ycqlPasswordMatches(bcryptCassandra, "cassandra") {
		t.Error("default cassandra password not recognized")
	}
	if ycqlPasswordMatches(bcryptCassandra, "dba") {
		t.Error("wrong password matched")
	}
	// Synthetic: no hash, only padding, or not bcrypt.
	for _, h := range []string{"", "\x00\x00", "cassandra"} {
		if ycqlPasswordMatches(h, "cassandra") {
			t.Errorf("hash %q matched", h)
		}
	}
}

func TestTrimNUL(t *testing.T) {
	if got := trimNUL("abc\x00\x00"); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := trimNUL("\x00"); got != "" {
		t.Errorf("got %q", got)
	}
}
