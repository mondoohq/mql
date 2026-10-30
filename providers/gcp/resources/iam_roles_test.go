// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestRoleGrantsIamPolicyManagement(t *testing.T) {
	cases := []struct {
		name  string
		perms []any
		want  bool
	}{
		{"setIamPolicy suffix", []any{"resourcemanager.projects.setIamPolicy"}, true},
		{"storage setIamPolicy", []any{"storage.buckets.setIamPolicy"}, true},
		{"only getIamPolicy", []any{"resourcemanager.projects.getIamPolicy"}, false},
		{"unrelated", []any{"compute.instances.list"}, false},
		{"empty", []any{}, false},
		{"non-string element ignored", []any{42, "x.setIamPolicy"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := roleGrantsIamPolicyManagement(&plugin.TValue[[]any]{Data: c.perms, State: plugin.StateIsSet})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("roleGrantsIamPolicyManagement(%v) = %v, want %v", c.perms, got, c.want)
			}
		})
	}
}

func TestRoleGrantsServiceAccountImpersonation(t *testing.T) {
	cases := []struct {
		name  string
		perms []any
		want  bool
	}{
		{"actAs", []any{"iam.serviceAccounts.actAs"}, true},
		{"getAccessToken", []any{"iam.serviceAccounts.getAccessToken"}, true},
		{"signJwt", []any{"iam.serviceAccounts.signJwt"}, true},
		{"list is not impersonation", []any{"iam.serviceAccounts.list"}, false},
		{"empty", []any{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := roleGrantsServiceAccountImpersonation(&plugin.TValue[[]any]{Data: c.perms, State: plugin.StateIsSet})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("roleGrantsServiceAccountImpersonation(%v) = %v, want %v", c.perms, got, c.want)
			}
		})
	}
}
