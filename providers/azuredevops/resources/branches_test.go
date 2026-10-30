// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// branchesOf is the branches of one repository, by name.
func branchesOf(t *testing.T, repo *mqlAzuredevopsRepository) map[string]*mqlAzuredevopsBranch {
	t.Helper()
	list := repo.GetBranches()
	require.NoError(t, list.Error)
	out := map[string]*mqlAzuredevopsBranch{}
	for _, b := range list.Data {
		branch := b.(*mqlAzuredevopsBranch)
		out[branch.Name.Data] = branch
	}
	return out
}

func TestRepositoryBranches(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repo := repositoriesOf(t, org)[fakeado.RepoIacID]

	branches := branchesOf(t, repo)
	require.Len(t, branches, 2, "the tag is not a branch")

	main := branches["main"]
	require.NotNil(t, main)
	assert.Equal(t, "refs/heads/main", main.RefName.Data)
	assert.Equal(t, "3c000000-0000-4000-8000-000000000321", main.HeadCommitSha.Data)
	assert.True(t, main.IsDefault.Data)

	release := branches["release/1.0"]
	require.NotNil(t, release)
	assert.Equal(t, "refs/heads/release/1.0", release.RefName.Data)
	assert.False(t, release.IsDefault.Data)
}

func TestTheSameBranchInTwoRepositoriesGivesTwoResources(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repos := repositoriesOf(t, org)

	iac := branchesOf(t, repos[fakeado.RepoIacID])["main"]
	app := branchesOf(t, repos[fakeado.RepoAppID])["main"]
	require.NotNil(t, iac)
	require.NotNil(t, app)
	assert.NotEqual(t, iac.__id, app.__id)
	assert.NotEqual(t, iac.HeadCommitSha.Data, app.HeadCommitSha.Data)
}

func TestARepositoryWithNoRefsHasNoBranches(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repo := repositoriesOf(t, org)[fakeado.RepoEmptyID]

	list := repo.GetBranches()
	require.NoError(t, list.Error)
	assert.False(t, list.IsNull())
	assert.Empty(t, list.Data)
}

func TestBranchesTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/refs")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	list := repo.GetBranches()
	assert.ErrorIs(t, list.Error, llx.ErrForbidden)
}
