// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultWorkspaceClientScopes pins the exact scope set the provider asks
// for. The list is what administrators paste into the domain-wide delegation
// grant, so drift between it and the scopes the resource code asserts breaks
// resources at runtime (unauthorized_client) or over-grants the delegation.
func TestDefaultWorkspaceClientScopes(t *testing.T) {
	want := []string{
		// directory
		"https://www.googleapis.com/auth/admin.directory.customer.readonly",
		"https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
		"https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
		"https://www.googleapis.com/auth/admin.directory.domain.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
		"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.user.security",
		// reports
		"https://www.googleapis.com/auth/admin.reports.audit.readonly",
		"https://www.googleapis.com/auth/admin.reports.usage.readonly",
		// calendar
		"https://www.googleapis.com/auth/calendar.readonly",
		"https://www.googleapis.com/auth/calendar.settings.readonly",
		"https://www.googleapis.com/auth/calendar.acls.readonly",
		// groups settings
		"https://www.googleapis.com/auth/apps.groups.settings",
		// cloud identity
		"https://www.googleapis.com/auth/cloud-identity.groups.readonly",
		"https://www.googleapis.com/auth/cloud-identity.devices.readonly",
		"https://www.googleapis.com/auth/cloud-identity.policies.readonly",
	}
	assert.ElementsMatch(t, want, DefaultWorkspaceClientScopes)
}

// TestDefaultWorkspaceClientScopesAreReadOnly guards against a write-capable
// scope sneaking onto a directory-wide delegation. admin.directory.user.security
// and apps.groups.settings have no read-only variant, so they are the only
// exceptions.
func TestDefaultWorkspaceClientScopesAreReadOnly(t *testing.T) {
	writeCapable := map[string]bool{
		"https://www.googleapis.com/auth/admin.directory.user.security": true,
		"https://www.googleapis.com/auth/apps.groups.settings":          true,
	}
	for _, scope := range DefaultWorkspaceClientScopes {
		if writeCapable[scope] {
			continue
		}
		assert.True(t, len(scope) > len(".readonly") && scope[len(scope)-len(".readonly"):] == ".readonly",
			"scope %q is not read-only and is not on the documented exception list", scope)
	}
}

func TestDefaultWorkspaceClientScopesHaveNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, scope := range DefaultWorkspaceClientScopes {
		require.False(t, seen[scope], "duplicate scope %q", scope)
		seen[scope] = true
	}
}
