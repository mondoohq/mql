// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/privilegedaccessmanager/apiv1/privilegedaccessmanagerpb"
)

func pamStrings(t *testing.T, in []any) []string {
	t.Helper()
	out := make([]string, 0, len(in))
	for _, v := range in {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("expected string element, got %T", v)
		}
		out = append(out, s)
	}
	return out
}

func assertPamStrings(t *testing.T, label string, got []any, want []string) {
	t.Helper()
	gotStrings := pamStrings(t, got)
	if len(gotStrings) != len(want) {
		t.Errorf("%s = %v, want %v", label, gotStrings, want)
		return
	}
	for i := range want {
		if gotStrings[i] != want[i] {
			t.Errorf("%s = %v, want %v", label, gotStrings, want)
			return
		}
	}
}

func TestPamEligiblePrincipals(t *testing.T) {
	t.Run("flattens and sorts across entries", func(t *testing.T) {
		got := pamEligiblePrincipals([]*privilegedaccessmanagerpb.AccessControlEntry{
			{Principals: []string{"user:zoe@example.com", "group:oncall@example.com"}},
			{Principals: []string{"user:adam@example.com"}},
		})
		assertPamStrings(t, "pamEligiblePrincipals", got, []string{
			"group:oncall@example.com",
			"user:adam@example.com",
			"user:zoe@example.com",
		})
	})

	t.Run("dedupes a principal named in several entries", func(t *testing.T) {
		got := pamEligiblePrincipals([]*privilegedaccessmanagerpb.AccessControlEntry{
			{Principals: []string{"user:alice@example.com"}},
			{Principals: []string{"user:alice@example.com"}},
		})
		assertPamStrings(t, "pamEligiblePrincipals", got, []string{"user:alice@example.com"})
	})

	t.Run("skips empty principals", func(t *testing.T) {
		got := pamEligiblePrincipals([]*privilegedaccessmanagerpb.AccessControlEntry{
			{Principals: []string{"", "user:bob@example.com"}},
		})
		assertPamStrings(t, "pamEligiblePrincipals", got, []string{"user:bob@example.com"})
	})

	t.Run("no entries", func(t *testing.T) {
		assertPamStrings(t, "pamEligiblePrincipals", pamEligiblePrincipals(nil), nil)
	})

	t.Run("entry with a nil principal list", func(t *testing.T) {
		got := pamEligiblePrincipals([]*privilegedaccessmanagerpb.AccessControlEntry{{}})
		assertPamStrings(t, "pamEligiblePrincipals", got, nil)
	})
}

func TestPamGrantedAccess(t *testing.T) {
	t.Run("extracts roles and resource from IAM access", func(t *testing.T) {
		access := &privilegedaccessmanagerpb.PrivilegedAccess{
			AccessType: &privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess_{
				GcpIamAccess: &privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess{
					ResourceType: "cloudresourcemanager.googleapis.com/Project",
					Resource:     "//cloudresourcemanager.googleapis.com/projects/my-project",
					RoleBindings: []*privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess_RoleBinding{
						{Role: "roles/owner"},
						{Role: "roles/iam.securityAdmin"},
					},
				},
			},
		}

		roles, resource := pamGrantedAccess(access)
		assertPamStrings(t, "grantedRoles", roles, []string{"roles/iam.securityAdmin", "roles/owner"})
		if want := "//cloudresourcemanager.googleapis.com/projects/my-project"; resource != want {
			t.Errorf("grantedResource = %q, want %q", resource, want)
		}
	})

	t.Run("dedupes a role bound twice", func(t *testing.T) {
		access := &privilegedaccessmanagerpb.PrivilegedAccess{
			AccessType: &privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess_{
				GcpIamAccess: &privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess{
					RoleBindings: []*privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess_RoleBinding{
						{Role: "roles/owner"},
						{Role: "roles/owner"},
					},
				},
			},
		}
		roles, _ := pamGrantedAccess(access)
		assertPamStrings(t, "grantedRoles", roles, []string{"roles/owner"})
	})

	// A nil access, or one carrying a form other than IAM access, must report no
	// roles rather than an empty-but-authoritative answer.
	t.Run("nil access", func(t *testing.T) {
		roles, resource := pamGrantedAccess(nil)
		assertPamStrings(t, "grantedRoles", roles, nil)
		if resource != "" {
			t.Errorf("grantedResource = %q, want empty", resource)
		}
	})

	t.Run("access with no IAM form", func(t *testing.T) {
		roles, resource := pamGrantedAccess(&privilegedaccessmanagerpb.PrivilegedAccess{})
		assertPamStrings(t, "grantedRoles", roles, nil)
		if resource != "" {
			t.Errorf("grantedResource = %q, want empty", resource)
		}
	})

	t.Run("skips empty role names", func(t *testing.T) {
		access := &privilegedaccessmanagerpb.PrivilegedAccess{
			AccessType: &privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess_{
				GcpIamAccess: &privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess{
					RoleBindings: []*privilegedaccessmanagerpb.PrivilegedAccess_GcpIamAccess_RoleBinding{
						{Role: ""},
						{Role: "roles/viewer"},
					},
				},
			},
		}
		roles, _ := pamGrantedAccess(access)
		assertPamStrings(t, "grantedRoles", roles, []string{"roles/viewer"})
	})
}
