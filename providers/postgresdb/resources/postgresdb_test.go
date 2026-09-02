// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"strings"
	"testing"
)

func TestClassifyPassword(t *testing.T) {
	// The values below are the tokens passwordFormExpr emits, plus the raw
	// shapes the classifier still tolerates. No real credential material is
	// used: the SCRAM and md5 bodies are placeholders.
	scramToken := "SCRAM-SHA-256$"
	scramRaw := "SCRAM-SHA-256$4096:AAAA$BBBB:CCCC"
	md5Token := "md5"
	md5Raw := "md5" + strings.Repeat("0", 32) // synthetic, not a real digest
	other := "other"
	plaintext := "plaintext"
	cases := []struct {
		name string
		in   *string
		want string
	}{
		// rolpassword IS NULL: the role has no password at all
		{"nil", nil, "none"},
		// the '' branch of passwordFormExpr
		{"empty", strPtr(""), "none"},
		// tokens as emitted by passwordFormExpr
		{"scram token", &scramToken, "scram-sha-256"},
		{"md5 token", &md5Token, "md5"},
		{"other token", &other, "other"},
		// raw catalog shapes must classify the same way, so the mapping is
		// unchanged for any caller holding a full rolpassword value
		{"scram raw", &scramRaw, "scram-sha-256"},
		{"md5 raw", &md5Raw, "md5"},
		{"plaintext", &plaintext, "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPassword(tc.in); got != tc.want {
				t.Errorf("classifyPassword = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPasswordFormExprEmitsOnlyDiscriminators pins the invariant this
// projection exists for: every branch yields NULL or a fixed token, so
// rolpassword itself never crosses the connection.
func TestPasswordFormExprEmitsOnlyDiscriminators(t *testing.T) {
	if strings.Contains(passwordFormExpr, "substring") || strings.Contains(passwordFormExpr, "left(") {
		t.Errorf("passwordFormExpr must not transfer a slice of the credential:\n%s", passwordFormExpr)
	}
	// rolpassword may only appear on the left of a comparison, never as a
	// THEN/ELSE result that would be sent to the client
	for _, result := range []string{"THEN NULL", "THEN ''", "THEN 'SCRAM-SHA-256$'", "THEN 'md5'", "ELSE 'other'"} {
		if !strings.Contains(passwordFormExpr, result) {
			t.Errorf("passwordFormExpr missing branch %q:\n%s", result, passwordFormExpr)
		}
	}
	if n := strings.Count(passwordFormExpr, "THEN rolpassword"); n != 0 {
		t.Errorf("passwordFormExpr returns the credential in %d branch(es)", n)
	}
}

// TestPasswordFormExprTokensRoundTrip proves the SQL tokens and the Go
// classifier agree, so the values reported by passwordType do not change.
func TestPasswordFormExprTokensRoundTrip(t *testing.T) {
	want := map[string]string{
		"SCRAM-SHA-256$": "scram-sha-256",
		"md5":            "md5",
		"other":          "other",
		"":               "none",
	}
	for token, expect := range want {
		if !strings.Contains(passwordFormExpr, "'"+token+"'") && token != "" {
			t.Errorf("passwordFormExpr does not emit token %q", token)
		}
		tok := token
		if got := classifyPassword(&tok); got != expect {
			t.Errorf("classifyPassword(%q) = %q, want %q", token, got, expect)
		}
	}
}

func strPtr(s string) *string { return &s }

func TestSanitizeConnInfo(t *testing.T) {
	cases := map[string]string{
		"host=remote dbname=x password=secret user=u": "host=remote dbname=x password=REDACTED user=u",
		"host=remote user=u":                          "host=remote user=u",
		"password=secret":                             "password=REDACTED",
		// single-quoted value with a space must be fully redacted
		"host=remote password='s3cret value' user=u": "host=remote password=REDACTED user=u",
		// URI-style connection strings must redact the password segment
		"postgresql://user:secret@host:5432/db": "postgresql://user:REDACTED@host:5432/db",
		// URI without a password is left unchanged
		"postgresql://user@host:5432/db": "postgresql://user@host:5432/db",
	}
	for in, want := range cases {
		if got := sanitizeConnInfo(in); got != want {
			t.Errorf("sanitizeConnInfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactOptions(t *testing.T) {
	got := redactOptions([]string{"user=remoteuser", "password=notreal", "PASSWORD=x", "host=remote"})
	want := []any{"user=remoteuser", "host=remote"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("redactOptions = %v, want %v", got, want)
	}
}

func TestIdentifierBuilders(t *testing.T) {
	if got := roleResourceID("SYS", "app_admin"); got != "app_admin@SYS" {
		t.Errorf("roleResourceID = %q", got)
	}
	if got := databaseResourceID("SYS", "appdb"); got != "SYS/appdb" {
		t.Errorf("databaseResourceID = %q", got)
	}
	// composite privilege id must vary by grantee and type
	a := privilegeResourceID("p", "PUBLIC", "CONNECT")
	b := privilegeResourceID("p", "PUBLIC", "TEMP")
	if a == b {
		t.Errorf("privilegeResourceID collides across type: %q", a)
	}
}
