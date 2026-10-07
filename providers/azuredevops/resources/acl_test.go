// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// permissionsOf reads the three permission fields of a branch protection.
func permissionsOf(t *testing.T, rules *mqlAzuredevopsBranchProtection) (forcePush, enforceAdmins, blockCreations *plugin.TValue[bool]) {
	t.Helper()
	return rules.GetAllowForcePushesEnabled(), rules.GetEnforceAdminsEnabled(), rules.GetBlockCreations()
}

func TestTheWeakRepositoryLetsContributorsForcePushBypassAndCreateBranches(t *testing.T) {
	for _, name := range []string{"main", "release/1.0"} {
		t.Run(name, func(t *testing.T) {
			forcePush, enforceAdmins, blockCreations := permissionsOf(t, rulesOf(t, branchOf(t, fakeado.RepoIacID, name)))
			require.NoError(t, forcePush.Error)
			require.NoError(t, enforceAdmins.Error)
			require.NoError(t, blockCreations.Error)

			assert.True(t, forcePush.Data, "the repository grants Contributors Force push")
			assert.False(t, enforceAdmins.Data, "the repository grants Contributors both bypass permissions")
			assert.False(t, blockCreations.Data, "Contributors keep Create branch from the project")
		})
	}
}

func TestTheStrongRepositoryGrantsNoPersonForcePushOrBypass(t *testing.T) {
	for _, name := range []string{"main", "release/1.0"} {
		t.Run(name, func(t *testing.T) {
			forcePush, enforceAdmins, blockCreations := permissionsOf(t, rulesOf(t, branchOf(t, fakeado.RepoAppID, name)))
			require.NoError(t, forcePush.Error)
			require.NoError(t, enforceAdmins.Error)
			require.NoError(t, blockCreations.Error)

			assert.False(t, forcePush.Data)
			assert.True(t, enforceAdmins.Data, "the build service holds Bypass policies when pushing, and it does not count")
			assert.True(t, blockCreations.Data, "the repository denies Contributors Create branch")
		})
	}
}

func TestPermissionsTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/accesscontrollists/" + connection.GitRepositoriesNamespace)
	b := branchesOf(t, repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID])["main"]
	require.NotNil(t, b)

	forcePush, enforceAdmins, blockCreations := permissionsOf(t, rulesOf(t, b))
	for _, v := range []*plugin.TValue[bool]{forcePush, enforceAdmins, blockCreations} {
		assert.ErrorIs(t, v.Error, llx.ErrForbidden)
	}
}

func TestBranchCreationIsForbiddenWhenTheGroupCannotBeRead(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/_apis/identities")
	b := branchesOf(t, repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID])["main"]
	require.NotNil(t, b)

	forcePush, _, blockCreations := permissionsOf(t, rulesOf(t, b))
	assert.ErrorIs(t, blockCreations.Error, llx.ErrForbidden)
	require.NoError(t, forcePush.Error)
	assert.False(t, forcePush.IsNull(), "the other permission fields do not need the group")
}

func TestBranchCreationIsNullWhenTheProjectHasNoContributorsGroup(t *testing.T) {
	b := branchOf(t, fakeado.RepoDocsID, "main")

	blockCreations := rulesOf(t, b).GetBlockCreations()
	require.NoError(t, blockCreations.Error)
	assert.True(t, blockCreations.IsNull())
}

func TestHeldByAPersonLeavesServiceIdentitiesOut(t *testing.T) {
	service := map[string]int64{"microsoft.teamfoundation.serviceidentity;x:build:y": connection.GitPermissionForcePush}
	assert.False(t, heldByAPerson(service, connection.GitPermissionForcePush))

	group := map[string]int64{"microsoft.teamfoundation.identity;s-1-9-1": connection.GitPermissionForcePush}
	assert.True(t, heldByAPerson(group, connection.GitPermissionForcePush))
	assert.False(t, heldByAPerson(group, connection.GitPermissionCreateBranch))
}
