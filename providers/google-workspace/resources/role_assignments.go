// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	directory "google.golang.org/api/admin/directory/v1"
)

// listRoleAssignments runs a paginated RoleAssignments.List, applying the
// optional roleId / userKey filters the directory API supports, and maps
// every assignment to a typed resource.
func listRoleAssignments(runtime *plugin.Runtime, roleId, userKey string) ([]any, error) {
	conn := runtime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryRolemanagementReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageToken := ""
	for {
		call := directoryService.RoleAssignments.List(conn.CustomerID()).MaxResults(200)
		if roleId != "" {
			call = call.RoleId(roleId)
		}
		if userKey != "" {
			call = call.UserKey(userKey)
		}
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		assignments, err := call.Do()
		if err != nil {
			return nil, err
		}
		for i := range assignments.Items {
			r, err := newMqlGoogleWorkspaceRoleAssignment(runtime, assignments.Items[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if assignments.NextPageToken == "" {
			break
		}
		pageToken = assignments.NextPageToken
	}
	return res, nil
}

// roleAssignmentData is the plain-struct projection of a
// directory.RoleAssignment used to build the resource.
type roleAssignmentData struct {
	ID           string
	RoleID       int64
	AssignedTo   string
	AssigneeType string
	ScopeType    string
	OrgUnitID    string
	Condition    string
	// ExpiresAt is nil for a standing assignment with no expiry.
	ExpiresAt *time.Time
}

// roleAssignmentToData projects a directory.RoleAssignment into the plain
// fields the resource exposes. RoleAssignmentId / RoleId are int64 on the SDK
// (string-encoded on the wire); the id field renders the assignment id as a
// decimal string.
func roleAssignmentToData(entry *directory.RoleAssignment) roleAssignmentData {
	return roleAssignmentData{
		ID:           strconv.FormatInt(entry.RoleAssignmentId, 10),
		RoleID:       entry.RoleId,
		AssignedTo:   entry.AssignedTo,
		AssigneeType: entry.AssigneeType,
		ScopeType:    entry.ScopeType,
		OrgUnitID:    entry.OrgUnitId,
		Condition:    entry.Condition,
		ExpiresAt:    roleAssignmentExpiry(entry),
	}
}

// roleAssignmentExpiry returns the RFC 3339 expireTime of a time-bound
// assignment, or nil when the assignment has no expirationDetails.
func roleAssignmentExpiry(entry *directory.RoleAssignment) *time.Time {
	if entry.ExpirationDetails == nil {
		return nil
	}
	return parseRFC3339(entry.ExpirationDetails.ExpireTime)
}

// isUserAssignee reports whether a role assignment's assignee is a user (as
// opposed to a group or service account). The directory API returns the
// assignee type lowercased.
func isUserAssignee(assigneeType string) bool {
	return assigneeType == "user"
}

func newMqlGoogleWorkspaceRoleAssignment(runtime *plugin.Runtime, entry *directory.RoleAssignment) (any, error) {
	d := roleAssignmentToData(entry)
	return CreateResource(runtime, "googleworkspace.role.assignment", map[string]*llx.RawData{
		"id":           llx.StringData(d.ID),
		"roleId":       llx.IntData(d.RoleID),
		"assignedTo":   llx.StringData(d.AssignedTo),
		"assigneeType": llx.StringData(d.AssigneeType),
		"scopeType":    llx.StringData(d.ScopeType),
		"orgUnitId":    llx.StringData(d.OrgUnitID),
		"condition":    llx.StringData(d.Condition),
		"expiresAt":    llx.TimeDataPtr(d.ExpiresAt),
	})
}

func (g *mqlGoogleworkspaceRoleAssignment) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "googleworkspace.role.assignment/" + g.Id.Data, nil
}

func (g *mqlGoogleworkspace) roleAssignments() ([]any, error) {
	return listRoleAssignments(g.MqlRuntime, "", "")
}

func (g *mqlGoogleworkspaceRole) assignments() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listRoleAssignments(g.MqlRuntime, strconv.FormatInt(g.Id.Data, 10), "")
}

func (g *mqlGoogleworkspaceRoleAssignment) role() (*mqlGoogleworkspaceRole, error) {
	if g.RoleId.Error != nil {
		return nil, g.RoleId.Error
	}
	parent, err := workspaceResource(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	role, err := parent.roleById(g.RoleId.Data)
	if err != nil {
		return nil, err
	}
	if role == nil {
		g.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

func (g *mqlGoogleworkspaceRoleAssignment) user() (*mqlGoogleworkspaceUser, error) {
	if g.AssigneeType.Error != nil {
		return nil, g.AssigneeType.Error
	}
	// assignedTo is an entity ID; only resolve it as a user when the assignee
	// is actually a user (it can also be a group or service account).
	if !isUserAssignee(g.AssigneeType.Data) {
		g.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.AssignedTo.Error != nil {
		return nil, g.AssignedTo.Error
	}

	parent, err := workspaceResource(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	user, err := parent.userById(g.AssignedTo.Data)
	if err != nil {
		return nil, err
	}
	if user == nil {
		g.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

func (g *mqlGoogleworkspaceUser) adminRoles() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	assignments, err := listRoleAssignments(g.MqlRuntime, "", g.Id.Data)
	if err != nil {
		return nil, err
	}

	parent, err := workspaceResource(g.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	seen := map[int64]struct{}{}
	for _, a := range assignments {
		assignment := a.(*mqlGoogleworkspaceRoleAssignment)
		if assignment.RoleId.Error != nil {
			return nil, assignment.RoleId.Error
		}
		roleId := assignment.RoleId.Data
		if _, dup := seen[roleId]; dup {
			continue
		}
		seen[roleId] = struct{}{}

		role, err := parent.roleById(roleId)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		res = append(res, role)
	}
	return res, nil
}
