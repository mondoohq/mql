// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Measured: Global Administrator's assignment on an E5 developer tenant,
// 2026-11-20. 150 directory roles, each with its own policy.
const (
	gaRoleID   = "62e90394-69f5-4237-9190-012177145e10"
	gaPolicyID = "Directory_2919c383-55f1-4d5b-9d3e-352998c3fd2b_a0ab3003-1708-4ae2-96b6-6f9f20cfefb7"
)

func pimAssignment(roleID, policyID string, withPolicy bool) models.UnifiedRoleManagementPolicyAssignmentable {
	a := models.NewUnifiedRoleManagementPolicyAssignment()
	if roleID != "" {
		a.SetRoleDefinitionId(ptr(roleID))
	}
	if policyID != "" {
		a.SetPolicyId(ptr(policyID))
	}
	if withPolicy {
		p := models.NewUnifiedRoleManagementPolicy()
		p.SetId(ptr(policyID))
		p.SetDisplayName(ptr("Directory"))
		p.SetScopeId(ptr("/"))
		p.SetScopeType(ptr("Directory"))
		a.SetPolicy(p)
	}
	return a
}

func TestIndexPimPolicyAssignments(t *testing.T) {
	byRole, byPolicy := indexPimPolicyAssignments([]models.UnifiedRoleManagementPolicyAssignmentable{
		pimAssignment(gaRoleID, gaPolicyID, true),
		// Synthetic: upper-case IDs, and assignments missing an ID; no target showed these.
		pimAssignment("E8611AB8-C189-46E8-94E1-60213AB1F814", "Directory_X_Y", false),
		pimAssignment("", "Directory_no_role", true),
		pimAssignment("fe930be7-5e62-47db-91af-98c3a49a38b1", "", true),
		nil,
	})

	require.Contains(t, byRole, gaRoleID)
	assert.Equal(t, gaPolicyID, *byRole[gaRoleID].GetId())
	assert.Equal(t, gaRoleID, byPolicy["directory_2919c383-55f1-4d5b-9d3e-352998c3fd2b_a0ab3003-1708-4ae2-96b6-6f9f20cfefb7"])

	// role keys are lower-cased; an assignment without an expanded policy
	// still links the policy to its role
	assert.Equal(t, "e8611ab8-c189-46e8-94e1-60213ab1f814", byPolicy["directory_x_y"])
	assert.NotContains(t, byRole, "e8611ab8-c189-46e8-94e1-60213ab1f814")

	assert.Len(t, byPolicy, 2)
	assert.Len(t, byRole, 1)
}

func pimTestEnv(t *testing.T) *plugin.Runtime {
	t.Helper()
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)
	res, err := CreateResource(runtime, "microsoft", map[string]*llx.RawData{})
	require.NoError(t, err)
	ms := res.(*mqlMicrosoft)
	ms.pimPolicies.once.Do(func() {
		ms.pimPolicies.policyByRole, ms.pimPolicies.roleByPolicy = indexPimPolicyAssignments(
			[]models.UnifiedRoleManagementPolicyAssignmentable{pimAssignment(gaRoleID, gaPolicyID, true)})
	})
	return runtime
}

func roleDefinitionWithID(t *testing.T, runtime *plugin.Runtime, id string) *mqlMicrosoftRolemanagementRoledefinition {
	t.Helper()
	res, err := CreateResource(runtime, ResourceMicrosoftRolemanagementRoledefinition, map[string]*llx.RawData{
		"id":          llx.StringData(id),
		"displayName": llx.StringData("role"),
	})
	require.NoError(t, err)
	return res.(*mqlMicrosoftRolemanagementRoledefinition)
}

func TestRoleDefinitionPimPolicy(t *testing.T) {
	runtime := pimTestEnv(t)

	// Graph returns role definition IDs in lower case, but the lookup must
	// not depend on it.
	ga := roleDefinitionWithID(t, runtime, "62E90394-69F5-4237-9190-012177145E10")
	policy, err := ga.pimPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, gaPolicyID, policy.Id.Data)

	// Synthetic: a role no policy is assigned to.
	unassigned := roleDefinitionWithID(t, runtime, "00000000-0000-0000-0000-000000000000")
	policy, err = unassigned.pimPolicy()
	require.NoError(t, err)
	assert.Nil(t, policy)
	assert.True(t, unassigned.PimPolicy.State&plugin.StateIsNull != 0)
}

func TestPimPolicyRoleDefinitionUnassigned(t *testing.T) {
	runtime := pimTestEnv(t)
	res, err := newMqlRoleManagementPolicy(runtime, func() models.UnifiedRoleManagementPolicyable {
		p := models.NewUnifiedRoleManagementPolicy()
		p.SetId(ptr("Directory_tenant_unassigned"))
		p.SetDisplayName(ptr("Directory"))
		return p
	}())
	require.NoError(t, err)
	policy := res.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy)

	role, err := policy.roleDefinition()
	require.NoError(t, err)
	assert.Nil(t, role)
	assert.True(t, policy.RoleDefinition.State&plugin.StateIsNull != 0)
}
