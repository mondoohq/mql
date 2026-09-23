// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	directory "google.golang.org/api/admin/directory/v1"
)

func TestRoleAssignmentToData(t *testing.T) {
	entry := &directory.RoleAssignment{
		RoleAssignmentId: 9876543210,
		RoleId:           12345,
		AssignedTo:       "103456789012345678901",
		AssigneeType:     "user",
		ScopeType:        "ORG_UNIT",
		OrgUnitId:        "03ph8a2z1xdnme9",
		Condition:        "api.getAttribute('...')",
	}

	d := roleAssignmentToData(entry)
	// int64 ids render as decimal strings (no scientific notation / truncation)
	require.Equal(t, "9876543210", d.ID)
	require.Equal(t, int64(12345), d.RoleID)
	require.Equal(t, "103456789012345678901", d.AssignedTo)
	require.Equal(t, "user", d.AssigneeType)
	require.Equal(t, "ORG_UNIT", d.ScopeType)
	require.Equal(t, "03ph8a2z1xdnme9", d.OrgUnitID)
	require.Equal(t, "api.getAttribute('...')", d.Condition)
}

func TestRoleAssignmentToData_GroupAssignee(t *testing.T) {
	d := roleAssignmentToData(&directory.RoleAssignment{
		RoleAssignmentId: 1,
		RoleId:           2,
		AssignedTo:       "01234567890",
		AssigneeType:     "group",
		ScopeType:        "CUSTOMER",
	})
	require.Equal(t, "group", d.AssigneeType)
	require.Empty(t, d.OrgUnitID)
	require.Empty(t, d.Condition)
	require.Nil(t, d.ExpiresAt)
}

func TestIsUserAssignee(t *testing.T) {
	require.True(t, isUserAssignee("user"))
	require.False(t, isUserAssignee("group"))
	require.False(t, isUserAssignee("USER")) // API returns lowercase; guard against case drift
	require.False(t, isUserAssignee(""))
}

// decodeRoleAssignment runs API-shaped JSON through the SDK struct, so a
// wrong json tag or nesting on expirationDetails shows up as a nil expiry.
func decodeRoleAssignment(t *testing.T, raw string) roleAssignmentData {
	t.Helper()
	var entry directory.RoleAssignment
	require.NoError(t, json.Unmarshal([]byte(raw), &entry))
	return roleAssignmentToData(&entry)
}

func TestRoleAssignmentExpiry_TimeBound(t *testing.T) {
	d := decodeRoleAssignment(t, `{
		"kind": "admin#directory#roleAssignment",
		"roleAssignmentId": "1234567890",
		"roleId": "9876543210",
		"assignedTo": "100000000000000000001",
		"assigneeType": "user",
		"scopeType": "CUSTOMER",
		"expirationDetails": {"expireTime": "2026-10-01T12:30:00.123Z"}
	}`)
	require.Equal(t, "1234567890", d.ID)
	require.NotNil(t, d.ExpiresAt)
	require.True(t, d.ExpiresAt.Equal(time.Date(2026, 10, 1, 12, 30, 0, 123000000, time.UTC)))
}

func TestRoleAssignmentExpiry_Standing(t *testing.T) {
	d := decodeRoleAssignment(t, `{
		"roleAssignmentId": "1",
		"roleId": "2",
		"assignedTo": "100000000000000000001",
		"assigneeType": "user",
		"scopeType": "CUSTOMER"
	}`)
	require.Nil(t, d.ExpiresAt)
}

func TestRoleAssignmentExpiry_EmptyOrUnparseable(t *testing.T) {
	d := decodeRoleAssignment(t, `{"roleAssignmentId": "1", "expirationDetails": {}}`)
	require.Nil(t, d.ExpiresAt)

	d = decodeRoleAssignment(t, `{"roleAssignmentId": "1", "expirationDetails": {"expireTime": "next tuesday"}}`)
	require.Nil(t, d.ExpiresAt)
}
