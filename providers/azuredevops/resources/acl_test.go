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

	// The repository list stands on its own, so the permissions are known and
	// only the group is missing.
	forcePush, enforceAdmins, blockCreations := permissionsOf(t, rulesOf(t, b))
	require.NoError(t, blockCreations.Error)
	assert.True(t, blockCreations.IsNull())
	require.NoError(t, forcePush.Error)
	assert.False(t, forcePush.IsNull(), "the other permission fields do not need the group")
	assert.False(t, forcePush.Data)
	require.NoError(t, enforceAdmins.Error)
	assert.False(t, enforceAdmins.IsNull(), "the other permission fields do not need the group")
	assert.True(t, enforceAdmins.Data)
}

// assertUnknown fails unless every field is null with no error. An unknown
// permission list must never read as the strongest posture.
func assertUnknown(t *testing.T, fields map[string]*plugin.TValue[bool]) {
	t.Helper()
	for name, v := range fields {
		require.NoError(t, v.Error, name)
		assert.True(t, v.IsNull(), "%s is unknown, not false or true", name)
	}
}

func TestPermissionsAreNullWhenTheProjectHasNoList(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.DropAccessControlList(connection.ProjectSecurityToken(fakeado.ProjectScanTestID))
	b := branchesOf(t, repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID])["main"]
	require.NotNil(t, b)

	forcePush, enforceAdmins, blockCreations := permissionsOf(t, rulesOf(t, b))
	assertUnknown(t, map[string]*plugin.TValue[bool]{
		"allowForcePushesEnabled": forcePush,
		"enforceAdminsEnabled":    enforceAdmins,
		"blockCreations":          blockCreations,
	})
}

func TestPermissionsAreNullWhenTheRepositoryHasNoProjectID(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	// More than two arguments skip the lookup, so the project id stays empty.
	res, err := CreateResource(runtime, "azuredevops.repository", repositoryArgs("scan-test", connection.Repository{
		ID:            fakeado.RepoIacID,
		Name:          "ado-scan-test-iac",
		DefaultBranch: "refs/heads/main",
	}))
	require.NoError(t, err)
	repo := res.(*mqlAzuredevopsRepository)
	require.Empty(t, repo.ProjectId.Data)
	b := branchesOf(t, repo)["main"]
	require.NotNil(t, b)

	forcePush, enforceAdmins, blockCreations := permissionsOf(t, rulesOf(t, b))
	assertUnknown(t, map[string]*plugin.TValue[bool]{
		"allowForcePushesEnabled": forcePush,
		"enforceAdminsEnabled":    enforceAdmins,
		"blockCreations":          blockCreations,
	})
	for _, req := range srv.Requests() {
		assert.NotContains(t, req, "accesscontrollists", "no list is asked for with an empty token")
	}
}

func TestPermissionsAreKnownOnlyWhenTheProjectListOrAStandaloneRepositoryListExists(t *testing.T) {
	list := func(inherit bool) *connection.AccessControlList {
		return &connection.AccessControlList{InheritPermissions: inherit}
	}
	cases := []struct {
		name          string
		project, repo *connection.AccessControlList
		want          bool
	}{
		{"neither list exists", nil, nil, false},
		{"only an inheriting repository list", nil, list(true), false},
		{"a repository list that does not inherit", nil, list(false), true},
		{"only the project list", list(true), nil, true},
		{"both lists", list(true), list(true), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, permissionsKnown(tc.project, tc.repo))
		})
	}
}

func TestHeldByAPersonLeavesServiceIdentitiesOut(t *testing.T) {
	service := map[string]int64{"microsoft.teamfoundation.serviceidentity;x:build:y": connection.GitPermissionForcePush}
	assert.False(t, heldByAPerson(service, connection.GitPermissionForcePush))

	group := map[string]int64{"microsoft.teamfoundation.identity;s-1-9-1": connection.GitPermissionForcePush}
	assert.True(t, heldByAPerson(group, connection.GitPermissionForcePush))
	assert.False(t, heldByAPerson(group, connection.GitPermissionCreateBranch))
}
