// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
)

//go:fix inline
func ptrAny(v any) *any { return new(v) }

// row builds a DESCRIBE property/value row with the given column casing.
func row(propKey, valKey, property, value string) map[string]*any {
	return map[string]*any{
		propKey: ptrAny(property),
		valKey:  ptrAny(value),
	}
}

func TestSessionPolicyDescribeProps(t *testing.T) {
	rows := []map[string]*any{
		row("property", "value", "SESSION_IDLE_TIMEOUT_MINS", "30"),
		// mixed-case column names must still match
		row("PROPERTY", "VALUE", "SESSION_UI_IDLE_TIMEOUT_MINS", "25"),
		row("property", "value", "COMMENT", "mql verify"),
		// a null value cell should map to an empty string, not panic
		{"property": ptrAny("SESSION_MAX_LIFESPAN_MINS"), "value": ptrAny(nil)},
		// a row missing the "value" key entirely must still map to an empty string
		{"property": ptrAny("SESSION_UI_MAX_LIFESPAN_MINS")},
	}
	props := sessionPolicyDescribeProps(rows)

	if props["SESSION_IDLE_TIMEOUT_MINS"] != "30" {
		t.Errorf("idle = %q, want 30", props["SESSION_IDLE_TIMEOUT_MINS"])
	}
	if props["SESSION_UI_IDLE_TIMEOUT_MINS"] != "25" {
		t.Errorf("ui = %q, want 25", props["SESSION_UI_IDLE_TIMEOUT_MINS"])
	}
	if props["COMMENT"] != "mql verify" {
		t.Errorf("comment = %q, want 'mql verify'", props["COMMENT"])
	}
	if v, ok := props["SESSION_MAX_LIFESPAN_MINS"]; !ok || v != "" {
		t.Errorf("max lifespan = %q (present=%v), want empty string present", v, ok)
	}
	if v, ok := props["SESSION_UI_MAX_LIFESPAN_MINS"]; !ok || v != "" {
		t.Errorf("ui max lifespan (missing value key) = %q (present=%v), want empty string present", v, ok)
	}
}

func TestParseSnowflakeInt(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"30", 30},
		{"  25  ", 25},
		{"0", 0},
		{"", 0},
		{"null", 0},
		{"not-a-number", 0},
		{"-5", -5},
	}
	for _, tc := range cases {
		if got := parseSnowflakeInt(tc.in); got != tc.want {
			t.Errorf("parseSnowflakeInt(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestUnsafeCellString(t *testing.T) {
	if got := unsafeCellString(nil); got != "" {
		t.Errorf("nil pointer = %q, want empty", got)
	}
	if got := unsafeCellString(ptrAny(nil)); got != "" {
		t.Errorf("pointer to nil = %q, want empty", got)
	}
	if got := unsafeCellString(ptrAny("  hello  ")); got != "hello" {
		t.Errorf("string = %q, want 'hello'", got)
	}
	if got := unsafeCellString(ptrAny(42)); got != "42" {
		t.Errorf("int = %q, want '42'", got)
	}
}
