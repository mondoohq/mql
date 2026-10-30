// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keystoneRoleAssignmentsBody is a /v3/role_assignments response covering the
// four shapes a deployment produces: a direct project grant, a domain grant
// inherited down to every project inside it, a system-wide grant, and a grant
// made to a group rather than a user.
const keystoneRoleAssignmentsBody = `{
  "role_assignments": [
    {
      "role": {"id": "role-member", "name": "member"},
      "user": {"id": "user-alice"},
      "scope": {"project": {"id": "project-web"}}
    },
    {
      "role": {"id": "role-admin", "name": "admin"},
      "user": {"id": "user-bob"},
      "scope": {
        "domain": {"id": "domain-default"},
        "OS-INHERIT:inherited_to": "projects"
      }
    },
    {
      "role": {"id": "role-admin", "name": "admin"},
      "user": {"id": "user-carol"},
      "scope": {"system": {"all": true}}
    },
    {
      "role": {"id": "role-reader", "name": "reader"},
      "group": {"id": "group-auditors"},
      "scope": {"project": {"id": "project-web"}}
    }
  ]
}`

func TestRoleAssignmentEntryScope(t *testing.T) {
	var body struct {
		RoleAssignments []roleAssignmentEntry `json:"role_assignments"`
	}
	require.NoError(t, json.Unmarshal([]byte(keystoneRoleAssignmentsBody), &body))
	require.Len(t, body.RoleAssignments, 4)

	tests := []struct {
		name      string
		scopeType string
		scopeID   string
		inherited bool
		roleName  string
		userID    string
		groupID   string
	}{
		{
			name:      "direct project grant",
			scopeType: "project",
			scopeID:   "project-web",
			roleName:  "member",
			userID:    "user-alice",
		},
		{
			name:      "domain grant inherited to projects",
			scopeType: "domain",
			scopeID:   "domain-default",
			inherited: true,
			roleName:  "admin",
			userID:    "user-bob",
		},
		{
			name:      "system-wide grant",
			scopeType: "system",
			scopeID:   "all",
			roleName:  "admin",
			userID:    "user-carol",
		},
		{
			name:      "grant to a group",
			scopeType: "project",
			scopeID:   "project-web",
			roleName:  "reader",
			groupID:   "group-auditors",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := body.RoleAssignments[i]
			scopeType, scopeID := a.scope()
			assert.Equal(t, tt.scopeType, scopeType)
			assert.Equal(t, tt.scopeID, scopeID)
			assert.Equal(t, tt.inherited, a.Scope.InheritedTo != "")
			assert.Equal(t, tt.roleName, a.Role.Name)
			assert.Equal(t, tt.userID, a.User.ID)
			assert.Equal(t, tt.groupID, a.Group.ID)
		})
	}
}

// A grant with no recognizable scope must not be reported as one, so a future
// scope type Keystone adds shows up as unknown rather than silently landing in
// the project or domain bucket.
func TestRoleAssignmentEntryScopeUnknown(t *testing.T) {
	var a roleAssignmentEntry
	require.NoError(t, json.Unmarshal([]byte(`{"scope": {"system": {"all": false}}}`), &a))
	scopeType, scopeID := a.scope()
	assert.Empty(t, scopeType)
	assert.Empty(t, scopeID)
}
