// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestSetting(t *testing.T) {
	m := map[string]string{
		"authenticator.class_name":      "PasswordAuthenticator",
		"authenticator":                 "OldName",
		"audit_logging_options.enabled": "true",
	}
	// Prefers the first present candidate (dotted class_name over the alias).
	if got := setting(m, "authenticator.class_name", "authenticator"); got != "PasswordAuthenticator" {
		t.Errorf("setting = %q, want PasswordAuthenticator", got)
	}
	// Falls back to a later candidate when the first is absent.
	if got := setting(m, "authorizer.class_name", "authenticator"); got != "OldName" {
		t.Errorf("setting fallback = %q, want OldName", got)
	}
	// Trims whitespace.
	m["x"] = "  y  "
	if got := setting(m, "x"); got != "y" {
		t.Errorf("setting trim = %q, want y", got)
	}
	// Empty when no candidate present.
	if got := setting(m, "nope"); got != "" {
		t.Errorf("setting missing = %q, want empty", got)
	}
}

func TestIsSystemKeyspace(t *testing.T) {
	for _, name := range []string{"system", "system_auth", "system_schema", "system_views"} {
		if !isSystemKeyspace(name) {
			t.Errorf("%q should be a system keyspace", name)
		}
	}
	for _, name := range []string{"app", "myks", "systemapp"} {
		if isSystemKeyspace(name) {
			t.Errorf("%q should not be a system keyspace", name)
		}
	}
}

func TestToAnySlice(t *testing.T) {
	got := toAnySlice([]string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("toAnySlice = %v", got)
	}
	if got := toAnySlice(nil); got == nil || len(got) != 0 {
		t.Errorf("toAnySlice(nil) = %v, want empty non-nil", got)
	}
}
