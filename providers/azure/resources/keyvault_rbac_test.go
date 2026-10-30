// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleAssignmentRoleDefinitionId pins the role definition ID onto the
// assignment itself.
//
// role() resolves the definition against the subscription's role listing and
// reports null for anything that listing does not cover, so before this field
// existed a grant made through a role defined elsewhere carried no trace of
// which role it was. Key Vault in RBAC mode is exactly that case: the grant is
// the only record of who can read the secrets, so losing the role identity
// loses the finding.
func TestRoleAssignmentRoleDefinitionId(t *testing.T) {
	const roleDefID = "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"

	t.Run("carries the role definition id", func(t *testing.T) {
		ra, err := newMqlRoleAssignment(cacheIDTestRuntime(), &authorization.RoleAssignment{
			ID:   new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/providers/Microsoft.Authorization/roleAssignments/a"),
			Name: new("a"),
			Properties: &authorization.RoleAssignmentProperties{
				PrincipalID:      new("11111111-1111-1111-1111-111111111111"),
				PrincipalType:    to.Ptr(authorization.PrincipalTypeServicePrincipal),
				RoleDefinitionID: to.Ptr(roleDefID),
				Scope:            new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v"),
			},
		})
		require.NoError(t, err)

		got, err := ra.roleDefinitionId()
		require.NoError(t, err)
		assert.Equal(t, roleDefID, got)
		assert.Equal(t, "ServicePrincipal", ra.PrincipalType.Data)
	})

	t.Run("empty when the assignment carries no role definition", func(t *testing.T) {
		ra, err := newMqlRoleAssignment(cacheIDTestRuntime(), &authorization.RoleAssignment{
			ID:         new("/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/b"),
			Name:       new("b"),
			Properties: &authorization.RoleAssignmentProperties{},
		})
		require.NoError(t, err)

		got, err := ra.roleDefinitionId()
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	// A nil Properties used to be a nil dereference; newMqlRoleAssignment
	// normalizes it. Pinned here because the role-definition read added a
	// second consumer of that normalization.
	t.Run("nil properties does not panic", func(t *testing.T) {
		ra, err := newMqlRoleAssignment(cacheIDTestRuntime(), &authorization.RoleAssignment{
			ID:   new("/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/c"),
			Name: new("c"),
		})
		require.NoError(t, err)

		got, err := ra.roleDefinitionId()
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}
