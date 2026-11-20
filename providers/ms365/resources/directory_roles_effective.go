// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	betarolemanagement "github.com/microsoftgraph/msgraph-beta-sdk-go/rolemanagement"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// directoryRoleIndex holds the tenant's directory role assignments and
// eligibilities, each read once, and the members of the groups they are
// granted to, read once per group. Only role-assignable groups can hold a
// directory role, and those cannot contain other groups, so a principal's
// roles are its own grants plus those of the groups it is a direct member of.
type directoryRoleIndex struct {
	assignOnce  sync.Once
	assignments []*mqlMicrosoftRolemanagementRoleassignment
	assignErr   error

	eligOnce      sync.Once
	eligibilities []*mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance
	eligErr       error

	membersMu    sync.Mutex
	groupMembers map[string]map[string]struct{}

	privOnce   sync.Once
	privileged map[string]*bool
	privErr    error
}

// directoryRoleMemberPageSize is the largest page Graph serves for group
// membership.
const directoryRoleMemberPageSize = int32(999)

// directoryRoleGrant is the part of a role assignment or eligibility that says
// who it was granted to.
type directoryRoleGrant struct {
	principalID   string
	principalType string
}

// grantsApplyingTo keeps the grants made to principalID, and, when
// throughGroups is set, those made to a group principalID is a member of.
// isMember answers group membership; it is only asked about groups that hold
// a grant.
func grantsApplyingTo[T any](grants []T, grantOf func(T) directoryRoleGrant, principalID string, throughGroups bool, isMember func(groupID string) (bool, error)) ([]any, error) {
	res := []any{}
	if principalID == "" {
		return res, nil
	}
	for _, g := range grants {
		grant := grantOf(g)
		if grant.principalID == "" {
			continue
		}
		if strings.EqualFold(grant.principalID, principalID) {
			res = append(res, g)
			continue
		}
		if !throughGroups || grant.principalType != "group" {
			continue
		}
		member, err := isMember(grant.principalID)
		if err != nil {
			return nil, err
		}
		if member {
			res = append(res, g)
		}
	}
	return res, nil
}

func (m *mqlMicrosoft) directoryRoleAssignmentList() ([]*mqlMicrosoftRolemanagementRoleassignment, error) {
	idx := &m.directoryRoles
	idx.assignOnce.Do(func() {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			idx.assignErr = err
			return
		}
		ctx := context.Background()
		// Listed without $expand=principal: Graph fails an expanded list
		// outright when one assignment names a deleted principal.
		resp, err := graphClient.RoleManagement().Directory().RoleAssignments().Get(ctx, nil)
		if err != nil {
			idx.assignErr = classifyGraphError(err, "RoleManagement.Read.Directory")
			return
		}
		assignments, err := iterate[models.UnifiedRoleAssignmentable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleAssignmentCollectionResponseFromDiscriminatorValue)
		if err != nil {
			idx.assignErr = transformError(err)
			return
		}
		ids := make([]string, 0, len(assignments))
		for _, a := range assignments {
			ids = append(ids, strVal(a.GetPrincipalId()))
		}
		principals, err := fetchDirectoryObjectsByIds(ctx, graphClient, uniqueNonEmpty(ids))
		if err != nil {
			idx.assignErr = err
			return
		}
		for _, a := range assignments {
			if a == nil || a.GetId() == nil {
				continue
			}
			r, err := newMqlDirectoryRoleAssignment(m.MqlRuntime, roleAssignmentRow{assignment: a, principal: principals[strVal(a.GetPrincipalId())]})
			if err != nil {
				idx.assignErr = err
				return
			}
			idx.assignments = append(idx.assignments, r)
		}
	})
	return idx.assignments, idx.assignErr
}

func (m *mqlMicrosoft) directoryRoleEligibilityList() ([]*mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance, error) {
	idx := &m.directoryRoles
	idx.eligOnce.Do(func() {
		ia, err := m.identityAndAccess()
		if err != nil {
			idx.eligErr = err
			return
		}
		list := ia.GetRoleEligibilityScheduleInstances()
		if list.Error != nil {
			idx.eligErr = list.Error
			return
		}
		for _, item := range list.Data {
			if inst, ok := item.(*mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance); ok {
				idx.eligibilities = append(idx.eligibilities, inst)
			}
		}
	})
	return idx.eligibilities, idx.eligErr
}

// isGroupMember reports whether memberID is a direct member of groupID,
// reading each group's member list once.
func (m *mqlMicrosoft) isGroupMember(groupID, memberID string) (bool, error) {
	idx := &m.directoryRoles
	idx.membersMu.Lock()
	defer idx.membersMu.Unlock()
	key := strings.ToLower(groupID)
	members, ok := idx.groupMembers[key]
	if !ok {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			return false, err
		}
		ctx := context.Background()
		top := directoryRoleMemberPageSize
		resp, err := graphClient.Groups().ByGroupId(groupID).Members().Get(ctx, &groups.ItemMembersRequestBuilderGetRequestConfiguration{
			QueryParameters: &groups.ItemMembersRequestBuilderGetQueryParameters{Top: &top, Select: []string{"id"}},
		})
		if err != nil {
			return false, classifyGraphError(err, "GroupMember.Read.All")
		}
		objs, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
		if err != nil {
			return false, transformError(err)
		}
		members = map[string]struct{}{}
		for _, o := range objs {
			if o != nil && o.GetId() != nil {
				members[strings.ToLower(*o.GetId())] = struct{}{}
			}
		}
		if idx.groupMembers == nil {
			idx.groupMembers = map[string]map[string]struct{}{}
		}
		idx.groupMembers[key] = members
	}
	_, member := members[strings.ToLower(memberID)]
	return member, nil
}

func assignmentGrant(a *mqlMicrosoftRolemanagementRoleassignment) directoryRoleGrant {
	return directoryRoleGrant{principalID: a.PrincipalId.Data, principalType: a.PrincipalType.Data}
}

func eligibilityGrant(e *mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance) directoryRoleGrant {
	return directoryRoleGrant{principalID: e.PrincipalId.Data, principalType: e.PrincipalType.Data}
}

func (m *mqlMicrosoft) directoryRoleAssignmentsFor(principalID string, throughGroups bool) ([]any, error) {
	all, err := m.directoryRoleAssignmentList()
	if err != nil {
		return nil, err
	}
	return grantsApplyingTo(all, assignmentGrant, principalID, throughGroups, func(groupID string) (bool, error) {
		return m.isGroupMember(groupID, principalID)
	})
}

func (m *mqlMicrosoft) directoryRoleEligibilitiesFor(principalID string, throughGroups bool) ([]any, error) {
	all, err := m.directoryRoleEligibilityList()
	if err != nil {
		return nil, err
	}
	return grantsApplyingTo(all, eligibilityGrant, principalID, throughGroups, func(groupID string) (bool, error) {
		return m.isGroupMember(groupID, principalID)
	})
}

func (a *mqlMicrosoftUser) directoryRoleAssignments() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.directoryRoleAssignmentsFor(a.Id.Data, true)
}

func (a *mqlMicrosoftUser) directoryRoleEligibilities() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.directoryRoleEligibilitiesFor(a.Id.Data, true)
}

func (a *mqlMicrosoftServiceprincipal) directoryRoleAssignments() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.directoryRoleAssignmentsFor(a.Id.Data, true)
}

func (a *mqlMicrosoftServiceprincipal) directoryRoleEligibilities() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.directoryRoleEligibilitiesFor(a.Id.Data, true)
}

func (a *mqlMicrosoftGroup) microsoftParent() (*mqlMicrosoft, error) {
	res, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoft), nil
}

func (a *mqlMicrosoftGroup) directoryRoleAssignments() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.directoryRoleAssignmentsFor(a.Id.Data, false)
}

func (a *mqlMicrosoftGroup) directoryRoleEligibilities() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.directoryRoleEligibilitiesFor(a.Id.Data, false)
}

// privilegedRoles reads Microsoft's privileged classification of every
// directory role definition once, from the beta endpoint that carries it.
func (m *mqlMicrosoft) privilegedRoles() (map[string]*bool, error) {
	idx := &m.directoryRoles
	idx.privOnce.Do(func() {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		client, err := conn.BetaGraphClient()
		if err != nil {
			idx.privErr = err
			return
		}
		ctx := context.Background()
		resp, err := client.RoleManagement().Directory().RoleDefinitions().Get(ctx, &betarolemanagement.DirectoryRoleDefinitionsRequestBuilderGetRequestConfiguration{
			QueryParameters: &betarolemanagement.DirectoryRoleDefinitionsRequestBuilderGetQueryParameters{Select: []string{"id", "isPrivileged"}},
		})
		if err != nil {
			idx.privErr = classifyGraphError(err, "RoleManagement.Read.Directory")
			return
		}
		defs, err := iterate[betamodels.UnifiedRoleDefinitionable](ctx, resp, client.GetAdapter(), betamodels.CreateUnifiedRoleDefinitionCollectionResponseFromDiscriminatorValue)
		if err != nil {
			idx.privErr = transformError(err)
			return
		}
		idx.privileged = privilegedByID(defs)
	})
	return idx.privileged, idx.privErr
}

func (a *mqlMicrosoftRolemanagementRoledefinition) isPrivileged() (bool, error) {
	res, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return false, err
	}
	privileged, err := res.(*mqlMicrosoft).privilegedRoles()
	if err != nil {
		return false, err
	}
	v := privileged[strings.ToLower(a.Id.Data)]
	if v == nil {
		a.IsPrivileged.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

// privilegedByID keys Microsoft's privileged classification by lower-cased
// role definition id. A definition Graph returned without the flag maps to nil.
func privilegedByID(defs []betamodels.UnifiedRoleDefinitionable) map[string]*bool {
	res := make(map[string]*bool, len(defs))
	for _, d := range defs {
		if d == nil || d.GetId() == nil || *d.GetId() == "" {
			continue
		}
		res[strings.ToLower(*d.GetId())] = d.GetIsPrivileged()
	}
	return res
}
