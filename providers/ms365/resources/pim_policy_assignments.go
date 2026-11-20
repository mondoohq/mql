// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	graphpolicies "github.com/microsoftgraph/msgraph-sdk-go/policies"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// pimPolicyAssignmentFilter selects the PIM policies assigned to directory
// roles at the tenant scope. Graph requires the scope in the filter.
const pimPolicyAssignmentFilter = "scopeId eq '/' and scopeType eq 'Directory'"

// pimPolicyIndex maps directory roles to the PIM policies that govern them at
// the tenant scope, both ways. One request with the policy expanded reads all
// of them, so resolving a role's policy never costs a call per role.
type pimPolicyIndex struct {
	once         sync.Once
	policyByRole map[string]models.UnifiedRoleManagementPolicyable
	roleByPolicy map[string]string
	err          error
}

// indexPimPolicyAssignments keys the assignments by role definition ID and by
// policy ID, lower-cased since both are GUID-based and Graph does not promise
// their case. An assignment missing either ID links nothing and is skipped.
func indexPimPolicyAssignments(assignments []models.UnifiedRoleManagementPolicyAssignmentable) (map[string]models.UnifiedRoleManagementPolicyable, map[string]string) {
	policyByRole := map[string]models.UnifiedRoleManagementPolicyable{}
	roleByPolicy := map[string]string{}
	for _, a := range assignments {
		if a == nil {
			continue
		}
		roleID := strings.ToLower(strVal(a.GetRoleDefinitionId()))
		policyID := strVal(a.GetPolicyId())
		if roleID == "" || policyID == "" {
			continue
		}
		roleByPolicy[strings.ToLower(policyID)] = roleID
		if p := a.GetPolicy(); p != nil && p.GetId() != nil {
			policyByRole[roleID] = p
		}
	}
	return policyByRole, roleByPolicy
}

// Least privileged permissions: RoleManagementPolicy.Read.Directory
func (m *mqlMicrosoft) pimPolicyAssignments() (*pimPolicyIndex, error) {
	idx := &m.pimPolicies
	idx.once.Do(func() {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			idx.err = err
			return
		}
		ctx := context.Background()
		filter := pimPolicyAssignmentFilter
		resp, err := graphClient.Policies().RoleManagementPolicyAssignments().Get(ctx, &graphpolicies.RoleManagementPolicyAssignmentsRequestBuilderGetRequestConfiguration{
			QueryParameters: &graphpolicies.RoleManagementPolicyAssignmentsRequestBuilderGetQueryParameters{
				Filter: &filter,
				Expand: []string{"policy"},
			},
		})
		if err != nil {
			idx.err = classifyGraphError(err, "RoleManagementPolicy.Read.Directory")
			return
		}
		if resp == nil {
			idx.policyByRole, idx.roleByPolicy = indexPimPolicyAssignments(nil)
			return
		}
		assignments, err := iterate[models.UnifiedRoleManagementPolicyAssignmentable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleManagementPolicyAssignmentCollectionResponseFromDiscriminatorValue)
		if err != nil {
			idx.err = classifyGraphError(err, "RoleManagementPolicy.Read.Directory")
			return
		}
		idx.policyByRole, idx.roleByPolicy = indexPimPolicyAssignments(assignments)
	})
	return idx, idx.err
}

func (a *mqlMicrosoftRolemanagementRoledefinition) pimPolicy() (*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy, error) {
	root, err := escrowMicrosoftRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	idx, err := root.pimPolicyAssignments()
	if err != nil {
		return nil, err
	}
	policy, ok := idx.policyByRole[strings.ToLower(a.Id.Data)]
	if !ok {
		a.PimPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := newMqlRoleManagementPolicy(a.MqlRuntime, policy)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy), nil
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy) roleDefinition() (*mqlMicrosoftRolemanagementRoledefinition, error) {
	root, err := escrowMicrosoftRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	idx, err := root.pimPolicyAssignments()
	if err != nil {
		return nil, err
	}
	roleID, ok := idx.roleByPolicy[strings.ToLower(a.Id.Data)]
	if !ok {
		a.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftRolemanagementRoledefinition, map[string]*llx.RawData{
		"id": llx.StringData(roleID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftRolemanagementRoledefinition), nil
}
