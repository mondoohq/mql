// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

const (
	publicMemberAllUsers              = "allUsers"
	publicMemberAllAuthenticatedUsers = "allAuthenticatedUsers"
)

func isPublicMember(s string) bool {
	return s == publicMemberAllUsers || s == publicMemberAllAuthenticatedUsers
}

// iamPolicyHasPublicMember returns true when any binding member is allUsers
// or allAuthenticatedUsers. The input is the .Data of an iamPolicy() TValue —
// each element is expected to be a *mqlGcpResourcemanagerBinding.
func iamPolicyHasPublicMember(bindings []any) (bool, error) {
	for _, raw := range bindings {
		binding, ok := raw.(*mqlGcpResourcemanagerBinding)
		if !ok || binding == nil {
			continue
		}
		members := binding.GetMembers()
		if members.Error != nil {
			return false, members.Error
		}
		for _, m := range members.Data {
			if s, ok := m.(string); ok && isPublicMember(s) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (b *mqlGcpResourcemanagerBinding) hasExternalMembers() (bool, error) {
	if b.Members.Error != nil {
		return false, b.Members.Error
	}
	for _, m := range b.Members.Data {
		if s, ok := m.(string); ok && isPublicMember(s) {
			return true, nil
		}
	}
	return false, nil
}

func (b *mqlGcpResourcemanagerBinding) isPrimitiveRole() (bool, error) {
	if b.Role.Error != nil {
		return false, b.Role.Error
	}
	switch b.Role.Data {
	case "roles/owner", "roles/editor", "roles/viewer":
		return true, nil
	}
	return false, nil
}

func (b *mqlGcpResourcemanagerBinding) grantsImpersonation() (bool, error) {
	if b.Role.Error != nil {
		return false, b.Role.Error
	}
	switch b.Role.Data {
	case "roles/iam.serviceAccountTokenCreator",
		"roles/iam.serviceAccountUser",
		"roles/iam.workloadIdentityUser",
		"roles/iam.serviceAccountKeyAdmin":
		return true, nil
	}
	return false, nil
}

// publicFromIamPolicy derives a public() field from its resource's
// iamPolicy(). A policy that could not be read (null, as a refused
// GetIamPolicy reads without structured errors) makes public null too: a
// refusal must not read as "not public". An empty policy is a real answer
// and reads false.
func publicFromIamPolicy(field *plugin.TValue[bool], bindings *plugin.TValue[[]any]) (bool, error) {
	if bindings.Error != nil {
		return false, bindings.Error
	}
	if bindings.Data == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return iamPolicyHasPublicMember(bindings.Data)
}
