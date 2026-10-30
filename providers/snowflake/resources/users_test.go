// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestParseSecondaryRoles(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []any
	}{
		{"empty", "", []any{}},
		{"empty json array", "[]", []any{}},
		{"whitespace", "  ", []any{}},
		{"all", `["ALL"]`, []any{"ALL"}},
		{"multiple", `["ALL","ANALYST"]`, []any{"ALL", "ANALYST"}},
		{"bare fallback", "ALL", []any{"ALL"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseSecondaryRoles(c.raw)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseSecondaryRoles(%q) = %#v, want %#v", c.raw, got, c.want)
			}
		})
	}
}
