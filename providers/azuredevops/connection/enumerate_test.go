// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestEnumerateListsEveryProject(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)

	// The server pages the projects, so all four prove the walk followed the
	// continuation token.
	var names []string
	for _, p := range listing.Projects {
		names = append(names, p.Project.Name)
	}
	assert.Equal(t, []string{"scan-test", "scan test", "locked-down", "legacy-apps"}, names)
}

func TestEnumerateKeepsAnUnreadableProjectWithoutFailing(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err, "one project the principal cannot read must not fail the organization")

	assert.Equal(t, []string{"locked-down"}, listing.Unreadable())
	for _, p := range listing.Projects {
		if p.Project.Name == "locked-down" {
			assert.Empty(t, p.Repos)
			assert.True(t, IsNoAccess(p.NoAccess), "the project records the answer Azure DevOps gave")
			continue
		}
		assert.NoError(t, p.NoAccess, p.Project.Name)
	}
	// The readable projects still produce repositories.
	assert.Len(t, listing.Repos(), 6)
}

func TestEnumerateFailsOnOtherErrors(t *testing.T) {
	// A bad token is not "a project the principal cannot read": it fails the
	// call on the first request, so a typo in a secret is not read as an empty
	// organization.
	c, _, _ := newFakeClient(t, entraAuth(t, "a-token-the-server-refuses"))

	_, err := c.Enumerate(context.Background())
	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestRepositoryStatus(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)

	got := map[string]RepoStatus{}
	for _, r := range listing.Repos() {
		got[r.Repo.ID] = r.Repo.Status()
	}
	assert.Equal(t, RepoReady, got[fakeado.RepoIacID])
	assert.Equal(t, RepoReady, got[fakeado.RepoAppID])
	assert.Equal(t, RepoEmpty, got[fakeado.RepoEmptyID], "no default branch means no commits")
	assert.Equal(t, RepoDisabled, got[fakeado.RepoRetiredID])
	assert.Equal(t, RepoReady, got[fakeado.RepoDocsID])
}

func TestStatusDisabledWinsOverEmpty(t *testing.T) {
	assert.Equal(t, RepoDisabled, Repository{IsDisabled: true}.Status())
	assert.Equal(t, RepoEmpty, Repository{}.Status())
	assert.Equal(t, RepoReady, Repository{DefaultBranch: "refs/heads/main"}.Status())
}

func TestListingKeepsRepositoriesWithTheSameNameApart(t *testing.T) {
	c, _, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err)

	var same []ListedRepo
	for _, r := range listing.Repos() {
		if r.Repo.Name == "ado-scan-test-iac" {
			same = append(same, r)
		}
	}
	require.Len(t, same, 2, "the name is repeated in two projects")
	assert.NotEqual(t, same[0].Repo.ID, same[1].Repo.ID)
	assert.NotEqual(t, same[0].FullName(), same[1].FullName())

	// The platform ids differ too, which is what keeps the two assets apart.
	idA := NewRepoIdentifier(fakeado.Org, same[0].Project.Name, same[0].Repo.Name)
	idB := NewRepoIdentifier(fakeado.Org, same[1].Project.Name, same[1].Repo.Name)
	assert.NotEqual(t, idA, idB)
}

func TestFullName(t *testing.T) {
	l := ListedRepo{Project: Project{Name: "scan test"}, Repo: Repository{Name: "ado-scan-test-iac"}}
	assert.Equal(t, "scan test/ado-scan-test-iac", l.FullName())
}

func TestEnumerateKeepsAProjectThatAnswers404(t *testing.T) {
	// Azure DevOps often answers 404 (TF401019), not 403, for the repository
	// list of a project the principal cannot see. It is the same case as
	// locked-down, so it is reported and skipped, not an organization failure.
	c, srv, _ := newFakeClient(t, entraAuth(t, fakeado.BearerToken))
	srv.HideRepositories("legacy-apps")

	listing, err := c.Enumerate(context.Background())
	require.NoError(t, err, "a project that answers 404 must not fail the organization")

	assert.Equal(t, []string{"locked-down", "legacy-apps"}, listing.Unreadable())
	for _, p := range listing.Projects {
		if p.Project.Name != "legacy-apps" {
			continue
		}
		assert.Empty(t, p.Repos)
		assert.True(t, IsNotFound(p.NoAccess), "the project records the 404 Azure DevOps gave")
		assert.False(t, IsNoAccess(p.NoAccess), "a 404 stays outside IsNoAccess, which is 401 and 403 only")
	}
}
