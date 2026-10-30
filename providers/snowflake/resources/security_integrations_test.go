// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestParseSnowflakeBool(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"true", true},
		{"false", false},
		{"  true  ", true},
		{"", false},
		{"TRUE", true},
		{"1", true},
		{"0", false},
		{"not-a-bool", false},
	}
	for _, tc := range cases {
		if got := parseSnowflakeBool(tc.in); got != tc.want {
			t.Errorf("parseSnowflakeBool(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
