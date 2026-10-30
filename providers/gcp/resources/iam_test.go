// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestBindingMembersInclude(t *testing.T) {
	const sa = "serviceAccount:ci@proj.iam.gserviceaccount.com"
	cases := []struct {
		name    string
		members []any
		want    bool
	}{
		{"exact", []any{"user:a@example.com", sa}, true},
		{"case-insensitive email", []any{"serviceAccount:CI@proj.iam.gserviceaccount.com"}, true},
		{"deleted principal", []any{"deleted:" + sa + "?uid=123456789"}, false},
		{"other service account", []any{"serviceAccount:other@proj.iam.gserviceaccount.com"}, false},
		{"same email as user", []any{"user:ci@proj.iam.gserviceaccount.com"}, false},
		{"prefix only", []any{sa + ".evil"}, false},
		{"empty", []any{}, false},
		{"nil", nil, false},
		{"non-string element", []any{42, sa}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bindingMembersInclude(c.members, sa); got != c.want {
				t.Errorf("bindingMembersInclude(%v) = %v, want %v", c.members, got, c.want)
			}
		})
	}
}

func TestIsAdminRole(t *testing.T) {
	cases := map[string]bool{
		"roles/owner":                           true,
		"roles/editor":                          true,
		"roles/viewer":                          false,
		"roles/compute.admin":                   true,
		"roles/iam.serviceAccountAdmin":         true,
		"roles/resourcemanager.projectIamAdmin": true,
		"projects/p/roles/DeployAdmin":          true,
		"organizations/1/roles/ADMIN_ROLE":      true,
		"roles/storage.objectViewer":            false,
		"roles/iam.serviceAccountUser":          false,
		"projects/p/roles/deployer":             false,
		"":                                      false,
	}
	for role, want := range cases {
		if got := isAdminRole(role); got != want {
			t.Errorf("isAdminRole(%q) = %v, want %v", role, got, want)
		}
	}
}
