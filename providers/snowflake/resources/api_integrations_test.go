// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestSplitPrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []any
	}{
		{"empty string", "", []any{}},
		{"whitespace only", "   ", []any{}},
		{"empty brackets", "[]", []any{}},
		{"single", "https://api.example.com/prod", []any{"https://api.example.com/prod"}},
		{"bracket wrapped", "[https://a.com/, https://b.com/]", []any{"https://a.com/", "https://b.com/"}},
		{"two values", "https://a.com/, https://b.com/", []any{"https://a.com/", "https://b.com/"}},
		{"empty entries dropped", "https://a.com/, , https://b.com/", []any{"https://a.com/", "https://b.com/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitPrefixes(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitPrefixes(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
