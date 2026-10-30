// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/stretchr/testify/assert"
)

func TestMatchesActionPattern(t *testing.T) {
	cases := []struct {
		pattern string
		action  string
		want    bool
	}{
		// exact matches, case-insensitive
		{"Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleAssignments/write", true},
		{"microsoft.authorization/roleassignments/write", "Microsoft.Authorization/roleAssignments/write", true},
		{"Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleAssignments/write", false},

		// bare wildcard is everything
		{"*", "Microsoft.Authorization/roleAssignments/write", true},

		// a trailing wildcard spans the remaining segments
		{"Microsoft.Authorization/*", "Microsoft.Authorization/roleAssignments/write", true},
		{"Microsoft.Compute/*", "Microsoft.Authorization/roleAssignments/write", false},

		// interior wildcards
		{"Microsoft.Authorization/*/write", "Microsoft.Authorization/roleAssignments/write", true},
		{"Microsoft.Authorization/*/read", "Microsoft.Authorization/roleAssignments/write", false},
		{"*/write", "Microsoft.Authorization/roleAssignments/write", true},
		{"*roleAssignments*", "Microsoft.Authorization/roleAssignments/write", true},

		// a wildcard matches zero characters
		{"Microsoft.Authorization/roleAssignments/write*", "Microsoft.Authorization/roleAssignments/write", true},
		{"*Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleAssignments/write", true},

		// prefix must anchor
		{"Authorization/*", "Microsoft.Authorization/roleAssignments/write", false},

		// empty pattern never matches
		{"", "Microsoft.Authorization/roleAssignments/write", false},
		{"", "", false},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, matchesActionPattern(c.pattern, c.action),
			"pattern %q against action %q", c.pattern, c.action)
	}
}

func perm(actions, notActions, dataActions, notDataActions []string) *authorization.Permission {
	p := &authorization.Permission{}
	for _, a := range actions {
		p.Actions = append(p.Actions, new(a))
	}
	for _, a := range notActions {
		p.NotActions = append(p.NotActions, new(a))
	}
	for _, a := range dataActions {
		p.DataActions = append(p.DataActions, new(a))
	}
	for _, a := range notDataActions {
		p.NotDataActions = append(p.NotDataActions, new(a))
	}
	return p
}

func TestGrantsAction(t *testing.T) {
	target := "Microsoft.Authorization/roleAssignments/write"

	t.Run("direct grant", func(t *testing.T) {
		assert.True(t, grantsAction([]*authorization.Permission{perm([]string{target}, nil, nil, nil)}, target))
	})
	t.Run("granted via wildcard", func(t *testing.T) {
		assert.True(t, grantsAction([]*authorization.Permission{perm([]string{"*"}, nil, nil, nil)}, target))
	})
	t.Run("notActions takes the wildcard grant back", func(t *testing.T) {
		// This is the built-in Contributor shape: everything except the ability
		// to hand out access.
		p := perm([]string{"*"}, []string{
			"Microsoft.Authorization/*/Delete",
			"Microsoft.Authorization/*/Write",
			"Microsoft.Authorization/elevateAccess/Action",
		}, nil, nil)
		assert.False(t, grantsAction([]*authorization.Permission{p}, target))
	})
	t.Run("notActions for an unrelated action does not block", func(t *testing.T) {
		p := perm([]string{"*"}, []string{"Microsoft.Compute/*/write"}, nil, nil)
		assert.True(t, grantsAction([]*authorization.Permission{p}, target))
	})
	t.Run("a second permission block can still grant", func(t *testing.T) {
		// NotActions only subtracts within its own block.
		blocked := perm([]string{"*"}, []string{"Microsoft.Authorization/*/write"}, nil, nil)
		allowed := perm([]string{target}, nil, nil, nil)
		assert.True(t, grantsAction([]*authorization.Permission{blocked, allowed}, target))
	})
	t.Run("no permissions grants nothing", func(t *testing.T) {
		assert.False(t, grantsAction(nil, target))
	})
	t.Run("nil permission entries are skipped", func(t *testing.T) {
		assert.False(t, grantsAction([]*authorization.Permission{nil}, target))
	})
}

func TestRoleIsPrivilegeEscalating(t *testing.T) {
	t.Run("Owner escalates", func(t *testing.T) {
		assert.True(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"*"}, nil, nil, nil),
		}))
	})
	t.Run("Contributor does not escalate", func(t *testing.T) {
		assert.False(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"*"}, []string{
				"Microsoft.Authorization/*/Delete",
				"Microsoft.Authorization/*/Write",
				"Microsoft.Authorization/elevateAccess/Action",
			}, nil, nil),
		}))
	})
	t.Run("User Access Administrator escalates", func(t *testing.T) {
		assert.True(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"*/read", "Microsoft.Authorization/*"}, nil, nil, nil),
		}))
	})
	t.Run("Reader does not escalate", func(t *testing.T) {
		assert.False(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"*/read"}, nil, nil, nil),
		}))
	})
	t.Run("a custom role granting only roleDefinitions/write escalates", func(t *testing.T) {
		// Authoring a role definition is escalation too: the holder can write a
		// permissive role and then assign it.
		assert.True(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"Microsoft.Authorization/roleDefinitions/write"}, nil, nil, nil),
		}))
	})
	t.Run("elevateAccess alone escalates", func(t *testing.T) {
		assert.True(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"Microsoft.Authorization/elevateAccess/action"}, nil, nil, nil),
		}))
	})
	t.Run("a compute-only custom role does not escalate", func(t *testing.T) {
		assert.False(t, roleIsPrivilegeEscalating([]*authorization.Permission{
			perm([]string{"Microsoft.Compute/virtualMachines/*", "Microsoft.Network/*/read"}, nil, nil, nil),
		}))
	})
}

func TestRoleHasWildcardActions(t *testing.T) {
	t.Run("bare wildcard", func(t *testing.T) {
		assert.True(t, roleHasWildcardActions([]*authorization.Permission{perm([]string{"*"}, nil, nil, nil)}))
	})
	t.Run("namespace wildcard", func(t *testing.T) {
		assert.True(t, roleHasWildcardActions([]*authorization.Permission{
			perm([]string{"Microsoft.Storage/storageAccounts/*"}, nil, nil, nil),
		}))
	})
	t.Run("fully enumerated actions have no wildcard", func(t *testing.T) {
		assert.False(t, roleHasWildcardActions([]*authorization.Permission{
			perm([]string{
				"Microsoft.Storage/storageAccounts/read",
				"Microsoft.Storage/storageAccounts/write",
			}, nil, nil, nil),
		}))
	})
	t.Run("a wildcard only in notActions does not count", func(t *testing.T) {
		assert.False(t, roleHasWildcardActions([]*authorization.Permission{
			perm([]string{"Microsoft.Storage/storageAccounts/read"}, []string{"Microsoft.Authorization/*"}, nil, nil),
		}))
	})
	t.Run("no permissions", func(t *testing.T) {
		assert.False(t, roleHasWildcardActions(nil))
	})
}

func TestRoleGrantsDataAccess(t *testing.T) {
	t.Run("blob data reader grants data access", func(t *testing.T) {
		assert.True(t, roleGrantsDataAccess([]*authorization.Permission{
			perm([]string{"Microsoft.Storage/storageAccounts/blobServices/containers/read"}, nil,
				[]string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}, nil),
		}))
	})
	t.Run("a control-plane-only role does not", func(t *testing.T) {
		assert.False(t, roleGrantsDataAccess([]*authorization.Permission{
			perm([]string{"Microsoft.Storage/storageAccounts/*"}, nil, nil, nil),
		}))
	})
	t.Run("totally negated data actions do not count", func(t *testing.T) {
		// Owner's shape: DataActions and NotDataActions both wildcard, which
		// grants no data access at the control plane.
		assert.False(t, roleGrantsDataAccess([]*authorization.Permission{
			perm([]string{"*"}, nil, []string{"*"}, []string{"*"}),
		}))
	})
	t.Run("partially negated data actions still grant", func(t *testing.T) {
		assert.True(t, roleGrantsDataAccess([]*authorization.Permission{
			perm(nil, nil,
				[]string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
				[]string{"Microsoft.Storage/storageAccounts/queueServices/*"}),
		}))
	})
	t.Run("empty data action strings are ignored", func(t *testing.T) {
		assert.False(t, roleGrantsDataAccess([]*authorization.Permission{
			perm(nil, nil, []string{""}, nil),
		}))
	})
}
