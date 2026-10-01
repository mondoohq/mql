// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// claude.organization.rbacGroup

type mqlClaudeOrganizationRbacGroupInternal struct {
	// cacheRoleIDs holds the group's attached role ids. Nil means the API
	// reported role data as temporarily unavailable, which is not the same
	// answer as a group with no roles.
	cacheRoleIDs []string
}

func (r *mqlClaudeOrganization) rbacGroups() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	groups, err := collectCursorPages(client.Beta.Organization.RBACGroups.List(
		context.Background(), anthropic.BetaOrganizationRBACGroupListParams{Limit: anthropic.Int(1000)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing rbac groups: %w", err), endpointUnavailable)
	}

	res := make([]interface{}, 0, len(groups))
	for _, g := range groups {
		mqlGroup, err := CreateResource(r.MqlRuntime, "claude.organization.rbacGroup", rbacGroupArgs(g))
		if err != nil {
			return nil, err
		}
		mqlGroup.(*mqlClaudeOrganizationRbacGroup).cacheRoleIDs = rbacGroupRoleIDs(g)
		res = append(res, mqlGroup)
	}
	return res, nil
}

// rbacGroupArgs maps an RBAC group onto resource arguments.
func rbacGroupArgs(g anthropic.BetaRBACGroup) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(g.ID),
		"id":         llx.StringData(g.ID),
		"name":       llx.StringData(g.Name),
		"sourceType": llx.StringDataPtr(nullableString(string(g.SourceType))),
		"createdAt":  llx.TimeDataPtr(nullableTime(g.CreatedAt)),
		"updatedAt":  llx.TimeDataPtr(nullableTime(g.UpdatedAt)),
	}
}

// rbacGroupRoleIDs returns the group's role ids, or nil when the API sent
// role_ids as null. A group with no roles comes back as an empty, non-nil
// slice so the two answers stay apart.
func rbacGroupRoleIDs(g anthropic.BetaRBACGroup) []string {
	if !g.JSON.RoleIDs.Valid() {
		return nil
	}
	if g.RoleIDs == nil {
		return []string{}
	}
	return g.RoleIDs
}

var errRoleDataUnavailable = errors.New("the API reported this group's role data as temporarily unavailable")

// roles resolves the group's role ids against the organization's role list,
// which is fetched once for every group.
func (r *mqlClaudeOrganizationRbacGroup) roles() ([]interface{}, error) {
	if r.cacheRoleIDs == nil {
		return nil, llx.Unavailable(errRoleDataUnavailable)
	}
	res := []interface{}{}
	for _, id := range r.cacheRoleIDs {
		role, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationRbacRole](
			r.MqlRuntime, id, (*mqlClaudeOrganization).GetRbacRoles)
		if err != nil {
			return nil, err
		}
		if ok {
			res = append(res, role)
		}
	}
	return res, nil
}

func (r *mqlClaudeOrganizationRbacGroup) members() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	groupID := r.Id.Data
	members, err := collectCursorPages(client.Beta.Organization.RBACGroups.Members.List(
		context.Background(), groupID, anthropic.BetaOrganizationRBACGroupMemberListParams{Limit: anthropic.Int(1000)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing members of rbac group %s: %w", groupID, err), parentMissing)
	}

	res := make([]interface{}, 0, len(members))
	for _, m := range members {
		mqlMember, err := CreateResource(r.MqlRuntime, "claude.organization.rbacGroup.member", rbacGroupMemberArgs(groupID, m))
		if err != nil {
			return nil, err
		}
		mqlMember.(*mqlClaudeOrganizationRbacGroupMember).cacheUserID = m.UserID
		res = append(res, mqlMember)
	}
	return res, nil
}

// claude.organization.rbacGroup.member

type mqlClaudeOrganizationRbacGroupMemberInternal struct {
	cacheUserID string
}

// rbacGroupMemberArgs maps a group membership onto resource arguments. A user
// belongs to many groups, so the membership is keyed by both ids.
func rbacGroupMemberArgs(groupID string, m anthropic.BetaRBACGroupMember) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":    llx.StringData(groupID + "/" + m.UserID),
		"email":   llx.StringDataPtr(nullableString(m.Email)),
		"addedAt": llx.TimeDataPtr(nullableTime(m.CreatedAt)),
	}
}

func (r *mqlClaudeOrganizationRbacGroupMember) user() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cacheUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.User.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

// claude.organization.rbacRole

func (r *mqlClaudeOrganization) rbacRoles() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	roles, err := collectCursorPages(client.Beta.Organization.RBACRoles.List(
		context.Background(), anthropic.BetaOrganizationRBACRoleListParams{Limit: anthropic.Int(1000)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing rbac roles: %w", err), endpointUnavailable)
	}

	res := make([]interface{}, 0, len(roles))
	for _, role := range roles {
		mqlRole, err := CreateResource(r.MqlRuntime, "claude.organization.rbacRole", map[string]*llx.RawData{
			"__id":      llx.StringData(role.ID),
			"id":        llx.StringData(role.ID),
			"name":      llx.StringData(role.Name),
			"createdAt": llx.TimeDataPtr(nullableTime(role.CreatedAt)),
			"updatedAt": llx.TimeDataPtr(nullableTime(role.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	return res, nil
}

func (r *mqlClaudeOrganizationRbacRole) permissions() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	roleID := r.Id.Data
	perms, err := collectCursorPages(client.Beta.Organization.RBACRoles.Permissions.List(
		context.Background(), roleID, anthropic.BetaOrganizationRBACRolePermissionListParams{Limit: anthropic.Int(1000)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing permissions of rbac role %s: %w", roleID, err), parentMissing)
	}

	res := make([]interface{}, 0, len(perms))
	for _, p := range perms {
		mqlPerm, err := CreateResource(r.MqlRuntime, "claude.organization.rbacRole.permission", rbacRolePermissionArgs(roleID, p))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPerm)
	}
	return res, nil
}

// rbacRolePermissionArgs maps a role permission onto resource arguments. A
// permission has no id of its own: it is the pair of an action and a target,
// so every part of both goes into the key. Leaving one out would let two
// grants on different connector tools share a cache entry and report one of
// them twice.
func rbacRolePermissionArgs(roleID string, p anthropic.BetaRBACRolePermission) map[string]*llx.RawData {
	res := p.Resource
	key := strings.Join([]string{roleID, res.Type, res.ConnectorID, res.ToolName, res.Scope, p.Action}, "/")
	return map[string]*llx.RawData{
		"__id":         llx.StringData(key),
		"action":       llx.StringData(p.Action),
		"resourceType": llx.StringDataPtr(nullableString(res.Type)),
		"connectorId":  llx.StringDataPtr(nullableString(res.ConnectorID)),
		"toolName":     llx.StringDataPtr(nullableString(res.ToolName)),
		"scope":        llx.StringDataPtr(nullableString(res.Scope)),
	}
}

// groups lists the groups the role is attached to. Role attachment is only
// reported from the group side, so the organization's group list, fetched
// once, is scanned for groups naming this role.
func (r *mqlClaudeOrganizationRbacRole) groups() ([]interface{}, error) {
	groups, err := organizationList(r.MqlRuntime, func(o *mqlClaudeOrganization) *plugin.TValue[[]interface{}] {
		return o.GetRbacGroups()
	})
	if err != nil {
		return nil, err
	}
	return groupsHoldingRole(groups, r.Id.Data)
}

// groupsHoldingRole returns the groups whose role ids include roleID. A group
// whose role data the API could not read makes the answer unknowable, so it
// is an error rather than a list that silently leaves the group out.
func groupsHoldingRole(groups []interface{}, roleID string) ([]interface{}, error) {
	res := []interface{}{}
	for _, item := range groups {
		group, ok := item.(*mqlClaudeOrganizationRbacGroup)
		if !ok {
			continue
		}
		if group.cacheRoleIDs == nil {
			return nil, llx.Unavailable(fmt.Errorf("rbac group %s: %w", group.Id.Data, errRoleDataUnavailable))
		}
		for _, id := range group.cacheRoleIDs {
			if id == roleID {
				res = append(res, group)
				break
			}
		}
	}
	return res, nil
}
