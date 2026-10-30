// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// roleArgs builds the resource args for an openai.role. The organization role
// list and the user, group, and project role-assignment lists all return the
// same role payload under different generated types, so every caller funnels
// through here with the fields already unpacked.
func roleArgs(id, name, description, resourceType string, permissions []string, predefined bool) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":         llx.StringData(id),
		"id":           llx.StringData(id),
		"name":         llx.StringData(name),
		"description":  llx.StringData(description),
		"permissions":  llx.ArrayData(convertStringSlice(permissions), "string"),
		"isPredefined": llx.BoolData(predefined),
		"resourceType": llx.StringData(resourceType),
	}
}

func convertStringSlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func (r *mqlOpenai) roles() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.roles")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Roles.ListAutoPaging(ctx, openai.AdminOrganizationRoleListParams{})
	var res []any
	for iter.Next() {
		role := iter.Current()
		mqlRole, err := CreateResource(r.MqlRuntime, "openai.role",
			roleArgs(role.ID, role.Name, role.Description, role.ResourceType, role.Permissions, role.PredefinedRole))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiOrganizationUser) roles() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.organizationUser.roles")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Users.Roles.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationUserRoleListParams{})
	var res []any
	for iter.Next() {
		role := iter.Current()
		mqlRole, err := CreateResource(r.MqlRuntime, "openai.role",
			roleArgs(role.ID, role.Name, role.Description, role.ResourceType, role.Permissions, role.PredefinedRole))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list roles for user %s: %w", r.Id.Data, err)
	}
	return res, nil
}

func mapGroup(g openai.Group) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":          llx.StringData(g.ID),
		"id":            llx.StringData(g.ID),
		"name":          llx.StringData(g.Name),
		"groupType":     llx.StringData(string(g.GroupType)),
		"isScimManaged": llx.BoolData(g.IsScimManaged),
		"createdAt":     llx.TimeDataPtr(unixToNullableTime(g.CreatedAt)),
	}
}

func (r *mqlOpenai) groups() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.groups")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Groups.ListAutoPaging(ctx, openai.AdminOrganizationGroupListParams{})
	var res []any
	for iter.Next() {
		g := iter.Current()
		mqlGroup, err := CreateResource(r.MqlRuntime, "openai.group", mapGroup(g))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	return res, nil
}

// initOpenaiGroup resolves a group from the organization group list rather than
// fetching it individually. Groups are referenced once per project they are
// granted access to, and the list is a single call whose resources the runtime
// then shares, so filtering in memory avoids a get per reference.
func initOpenaiGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	groupID, ok := idRaw.Value.(string)
	if !ok || groupID == "" {
		return args, nil, nil
	}

	groups, err := openaiGroupList(runtime)
	if err != nil {
		return nil, nil, err
	}
	for i := range groups {
		g, ok := groups[i].(*mqlOpenaiGroup)
		if !ok {
			continue
		}
		if g.Id.Data == groupID {
			return nil, g, nil
		}
	}
	return nil, nil, fmt.Errorf("openai.group with id %q not found", groupID)
}

// openaiGroupList returns the organization group collection through the openai
// resource so the underlying list call is made once per scan.
func openaiGroupList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	groups := obj.(*mqlOpenai).GetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	return groups.Data, nil
}

// openaiUserList returns the organization user collection through the openai
// resource so the underlying list call is made once per scan.
func openaiUserList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	users := obj.(*mqlOpenai).GetUsers()
	if users.Error != nil {
		return nil, users.Error
	}
	return users.Data, nil
}

// findOrganizationUser looks up the organization member with the given id and
// reports (nil, nil) when the organization does not list them. Records that
// name a user outlive the membership they name (an audit log entry and an API
// key both survive the member being removed), so those callers null the field
// instead of failing the collection they are part of.
func findOrganizationUser(runtime *plugin.Runtime, userID string) (*mqlOpenaiOrganizationUser, error) {
	users, err := openaiUserList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range users {
		u, ok := users[i].(*mqlOpenaiOrganizationUser)
		if !ok {
			continue
		}
		if u.Id.Data == userID {
			return u, nil
		}
	}
	return nil, nil
}

// resolveOrganizationUser finds the organization member with the given id.
// Admin API keys, project memberships, and group memberships all point at
// users by id, and all of them resolve against the one organization user list.
func resolveOrganizationUser(runtime *plugin.Runtime, userID string) (*mqlOpenaiOrganizationUser, error) {
	user, err := findOrganizationUser(runtime, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("openai.organizationUser with id %q not found", userID)
	}
	return user, nil
}

func initOpenaiOrganizationUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	userID, ok := idRaw.Value.(string)
	if !ok || userID == "" {
		return args, nil, nil
	}

	user, err := resolveOrganizationUser(runtime, userID)
	if err != nil {
		return nil, nil, err
	}
	return nil, user, nil
}

func (r *mqlOpenaiGroup) members() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.group.members")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Groups.Users.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationGroupUserListParams{})
	var res []any
	for iter.Next() {
		member := iter.Current()
		user, err := resolveOrganizationUser(r.MqlRuntime, member.ID)
		if err != nil {
			return nil, err
		}
		res = append(res, user)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list members of group %s: %w", r.Id.Data, err)
	}
	return res, nil
}

func (r *mqlOpenaiGroup) roles() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.group.roles")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Groups.Roles.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationGroupRoleListParams{})
	var res []any
	for iter.Next() {
		role := iter.Current()
		mqlRole, err := CreateResource(r.MqlRuntime, "openai.role",
			roleArgs(role.ID, role.Name, role.Description, role.ResourceType, role.Permissions, role.PredefinedRole))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list roles for group %s: %w", r.Id.Data, err)
	}
	return res, nil
}

type mqlOpenaiAdminApiKeyInternal struct {
	cacheOwnerId string
}

func (r *mqlOpenai) adminApiKeys() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.adminApiKeys")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.AdminAPIKeys.ListAutoPaging(ctx, openai.AdminOrganizationAdminAPIKeyListParams{})
	var res []any
	for iter.Next() {
		k := iter.Current()

		mqlKey, err := CreateResource(r.MqlRuntime, "openai.adminApiKey", map[string]*llx.RawData{
			"__id":          llx.StringData(k.ID),
			"id":            llx.StringData(k.ID),
			"name":          llx.StringData(k.Name),
			"redactedValue": llx.StringData(k.RedactedValue),
			"createdAt":     llx.TimeDataPtr(unixToNullableTime(k.CreatedAt)),
			"expiresAt":     llx.TimeDataPtr(unixToNullableTime(k.ExpiresAt)),
			"lastUsedAt":    llx.TimeDataPtr(unixToNullableTime(k.LastUsedAt)),
			"ownerType":     llx.StringData(k.Owner.Type),
			"ownerName":     llx.StringData(k.Owner.Name),
			"ownerRole":     llx.StringData(k.Owner.Role),
		})
		if err != nil {
			return nil, err
		}
		mqlKey.(*mqlOpenaiAdminApiKey).cacheOwnerId = k.Owner.ID
		res = append(res, mqlKey)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list admin API keys: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiAdminApiKey) owner() (*mqlOpenaiOrganizationUser, error) {
	if r.OwnerType.Data != "user" || r.cacheOwnerId == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOrganizationUser(r.MqlRuntime, r.cacheOwnerId)
}

type mqlOpenaiOrganizationUserRoleAssignmentInternal struct {
	cacheGroupIDs     []string
	cacheSourcesKnown bool
}

// roleAssignmentIsDirect reports whether an assignment source names a user
// principal, which is what separates a role granted to the member outright
// from one that arrives through a group. The second return value is false when
// the API reported no assignment sources at all, where neither answer is known
// and the field has to stay null: a fabricated false would let
// `.all(isDirect == false)` pass without anything having been read.
func roleAssignmentIsDirect(sources []openai.AdminOrganizationUserRoleListResponseAssignmentSource, sourcesReported bool) (bool, bool) {
	if !sourcesReported {
		return false, false
	}
	for _, src := range sources {
		if src.PrincipalType == "user" {
			return true, true
		}
	}
	return false, true
}

// roleAssignmentGroupIDs collects the groups an inherited role arrives
// through, in the order the API reported them.
func roleAssignmentGroupIDs(sources []openai.AdminOrganizationUserRoleListResponseAssignmentSource) []string {
	var groups []string
	for _, src := range sources {
		if src.PrincipalType == "group" && src.PrincipalID != "" {
			groups = append(groups, src.PrincipalID)
		}
	}
	return groups
}

func (r *mqlOpenaiOrganizationUser) roleAssignments() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.organizationUser.roleAssignments")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Admin.Organization.Users.Roles.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationUserRoleListParams{}),
		func(role openai.AdminOrganizationUserRoleListResponse) string { return role.ID },
		func(role openai.AdminOrganizationUserRoleListResponse) error {
			mqlRole, err := CreateResource(r.MqlRuntime, "openai.role",
				roleArgs(role.ID, role.Name, role.Description, role.ResourceType, role.Permissions, role.PredefinedRole))
			if err != nil {
				return err
			}

			sourcesReported := role.JSON.AssignmentSources.Valid()
			isDirect, known := roleAssignmentIsDirect(role.AssignmentSources, sourcesReported)
			var isDirectData *bool
			if known {
				isDirectData = &isDirect
			}

			// an assignment is scoped to the member it was read for, so a bare
			// role id would collide across every member holding the role
			mqlAssignment, err := CreateResource(r.MqlRuntime, "openai.organizationUser.roleAssignment", map[string]*llx.RawData{
				"__id":     llx.StringData(r.Id.Data + "/" + role.ID),
				"isDirect": llx.BoolDataPtr(isDirectData),
				"role":     llx.ResourceData(mqlRole, "openai.role"),
			})
			if err != nil {
				return err
			}
			assignment := mqlAssignment.(*mqlOpenaiOrganizationUserRoleAssignment)
			assignment.cacheSourcesKnown = sourcesReported
			assignment.cacheGroupIDs = roleAssignmentGroupIDs(role.AssignmentSources)
			res = append(res, mqlAssignment)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list role assignments for user %s: %w", r.Id.Data, err)
	}
	return res, nil
}

func (r *mqlOpenaiOrganizationUserRoleAssignment) inheritedFromGroups() ([]any, error) {
	if !r.cacheSourcesKnown {
		r.InheritedFromGroups.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, groupID := range r.cacheGroupIDs {
		mqlGroup, err := NewResource(r.MqlRuntime, "openai.group", map[string]*llx.RawData{
			"id": llx.StringData(groupID),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}
