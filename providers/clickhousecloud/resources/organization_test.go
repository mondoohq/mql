// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"testing"
)

func TestRoleNames(t *testing.T) {
	cases := []struct {
		name string
		in   []apiAssignedRole
		want []string
	}{
		{"admin", []apiAssignedRole{{RoleName: "Admin"}}, []string{"Admin"}},
		{"multiple", []apiAssignedRole{{RoleName: "Admin"}, {RoleName: "Developer"}}, []string{"Admin", "Developer"}},
		{"skips empty", []apiAssignedRole{{RoleName: ""}, {RoleName: "Admin"}}, []string{"Admin"}},
		{"none", nil, []string{}},
	}
	for _, c := range cases {
		if got := roleNames(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%s: roleNames(%+v) = %#v, want %#v", c.name, c.in, got, c.want)
		}
	}
}
