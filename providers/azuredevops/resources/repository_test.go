// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestSameRepositoryNameInTwoProjectsGivesTwoResources(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repos := repositoriesOf(t, org)

	a := repos[fakeado.RepoIacID]
	b := repos[fakeado.RepoIacSpace]
	require.NotNil(t, a)
	require.NotNil(t, b)

	assert.Equal(t, a.Name.Data, b.Name.Data, "the name is repeated")
	assert.Equal(t, "scan-test/ado-scan-test-iac", a.FullName.Data)
	assert.Equal(t, "scan test/ado-scan-test-iac", b.FullName.Data)
	assert.NotEqual(t, a.__id, b.__id)
}

func TestRepositoryStatusFields(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repos := repositoriesOf(t, org)

	ready := repos[fakeado.RepoAppID]
	assert.Equal(t, "ready", ready.Status.Data)
	assert.Equal(t, "refs/heads/main", ready.DefaultBranch.Data)
	assert.False(t, ready.IsEmpty.Data)
	assert.False(t, ready.IsDisabled.Data)

	empty := repos[fakeado.RepoEmptyID]
	assert.Equal(t, "empty", empty.Status.Data)
	assert.True(t, empty.IsEmpty.Data)
	assert.Empty(t, empty.DefaultBranch.Data)

	retired := repos[fakeado.RepoRetiredID]
	assert.Equal(t, "disabled", retired.Status.Data)
	assert.True(t, retired.IsDisabled.Data)
}

func TestRepositoryCloneURLCarriesNoUserInformation(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repo := repositoriesOf(t, org)[fakeado.RepoIacSpace]

	assert.Equal(t, "https://dev.azure.com/mondoo-ado-scan-test/scan%20test/_git/ado-scan-test-iac", repo.CloneUrl.Data)
	assert.NotContains(t, repo.CloneUrl.Data, "@")
}

func TestRepositoryInitFromARepositoryConnection(t *testing.T) {
	runtime := newRuntime(t, map[string]string{
		connection.OPTION_PROJECT:    "scan test",
		connection.OPTION_REPOSITORY: "ado-scan-test-iac",
	})

	res, err := NewResource(runtime, "azuredevops.repository", map[string]*llx.RawData{})
	require.NoError(t, err)
	repo := res.(*mqlAzuredevopsRepository)

	assert.Equal(t, fakeado.RepoIacSpace, repo.Id.Data)
	assert.Equal(t, "scan test/ado-scan-test-iac", repo.FullName.Data)
	assert.Equal(t, "ready", repo.Status.Data)
}

func TestRepositoryInitByProjectAndName(t *testing.T) {
	runtime := newRuntime(t, nil)

	res, err := NewResource(runtime, "azuredevops.repository", map[string]*llx.RawData{
		"projectName": llx.StringData("scan-test"),
		"name":        llx.StringData("ado-scan-test-app"),
	})
	require.NoError(t, err)
	repo := res.(*mqlAzuredevopsRepository)
	assert.Equal(t, fakeado.RepoAppID, repo.Id.Data)
}

func TestRepositoryInitWithoutAProjectFails(t *testing.T) {
	// an organization connection with no project and no name must not build a
	// blank repository whose every field reads null
	runtime := newRuntime(t, nil)

	_, err := NewResource(runtime, "azuredevops.repository", map[string]*llx.RawData{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a project and a name")
}

func TestRepositoryProject(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repo := repositoriesOf(t, org)[fakeado.RepoIacSpace]

	project := repo.GetProject()
	require.NoError(t, project.Error)
	assert.Equal(t, "scan test", project.Data.Name.Data)
}
