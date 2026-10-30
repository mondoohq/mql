// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestParseExternalAccessList(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []any
	}{
		{"empty", "", []any{}},
		{"empty brackets", "[]", []any{}},
		{"single", "[A]", []any{"A"}},
		{"multiple with whitespace", "[A, B, C]", []any{"A", "B", "C"}},
		{"bare without brackets", "A,B", []any{"A", "B"}},
		{"leading and trailing commas", "[,A,B,]", []any{"A", "B"}},
		{"embedded blank entry", "[A,,B]", []any{"A", "B"}},
		{"only commas", "[,,]", []any{}},
		{"surrounding whitespace outside brackets", "  [A, B]  ", []any{"A", "B"}},
		{"fully qualified names", "[DB.SCH.RULE1, DB.SCH.RULE2]", []any{"DB.SCH.RULE1", "DB.SCH.RULE2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseExternalAccessList(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseExternalAccessList(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

// ptr wraps a concrete value in an *any, mirroring the *any cells the Snowflake
// driver returns from QueryUnsafe.
//
//go:fix inline
func ptr(v any) *any {
	return new(v)
}

func TestUnsafeString(t *testing.T) {
	var nilAny *any // a genuinely nil *any pointer

	cases := []struct {
		name string
		in   *any
		want string
	}{
		{"nil pointer", nilAny, ""},
		{"pointer wrapping nil", ptr(nil), ""},
		{"string value", ptr("hello"), "hello"},
		{"empty string value", ptr(""), ""},
		{"bool true", ptr(true), "true"},
		{"bool false", ptr(false), "false"},
		{"int value", ptr(42), "42"},
		{"float value", ptr(3.5), "3.5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unsafeString(tc.in)
			if got != tc.want {
				t.Errorf("unsafeString(%#v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestUnsafeBool(t *testing.T) {
	var nilAny *any // a genuinely nil *any pointer

	cases := []struct {
		name string
		in   *any
		want bool
	}{
		{"nil pointer", nilAny, false},
		{"pointer wrapping nil", ptr(nil), false},
		{"bool true", ptr(true), true},
		{"bool false", ptr(false), false},
		{"string true", ptr("true"), true},
		{"string uppercase TRUE", ptr("TRUE"), true},
		{"string true with surrounding whitespace", ptr(" true "), true},
		{"string false", ptr("false"), false},
		{"empty string", ptr(""), false},
		// NOTE: only "true" (case-insensitive, trimmed) is truthy. Numeric
		// strings and other tokens are not coerced, so "1" is false.
		{"string one", ptr("1"), false},
		// NOTE: non-string/non-bool cells always yield false, even a nonzero int.
		{"int value", ptr(1), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unsafeBool(tc.in)
			if got != tc.want {
				t.Errorf("unsafeBool(%#v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
