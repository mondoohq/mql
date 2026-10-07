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

// policiesOf is the policies that apply to one repository, by id.
func policiesOf(t *testing.T, repo *mqlAzuredevopsRepository) map[int64]*mqlAzuredevopsPolicy {
	t.Helper()
	list := repo.GetPolicies()
	require.NoError(t, list.Error)
	out := map[int64]*mqlAzuredevopsPolicy{}
	for _, p := range list.Data {
		policy := p.(*mqlAzuredevopsPolicy)
		out[policy.Id.Data] = policy
	}
	return out
}

func TestRepositoryPoliciesAreTheOnesThatNameItOrEveryRepository(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repos := repositoriesOf(t, org)

	iac := policiesOf(t, repos[fakeado.RepoIacID])
	assert.ElementsMatch(t, []int64{11, 12, 31}, keys(iac), "13 is deleted, 21-25 belong to the other repository")

	app := policiesOf(t, repos[fakeado.RepoAppID])
	assert.ElementsMatch(t, []int64{21, 22, 23, 24, 25, 31}, keys(app))
}

func TestPolicyFields(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	p := policiesOf(t, repositoriesOf(t, org)[fakeado.RepoIacID])[11]
	require.NotNil(t, p)

	assert.Equal(t, connection.PolicyTypeMinimumReviewers, p.Type.Data)
	assert.Equal(t, "Minimum number of reviewers", p.TypeName.Data)
	assert.True(t, p.Enabled.Data)
	assert.True(t, p.Blocking.Data)
	assert.Equal(t, []any{map[string]any{
		"repositoryId": fakeado.RepoIacID,
		"refName":      "refs/heads/main",
		"matchKind":    "Exact",
	}}, p.Scope.Data)
	assert.Equal(t, float64(1), p.Settings.Data.(map[string]any)["minimumApproverCount"])
	assert.NotContains(t, p.Settings.Data.(map[string]any), "scope", "the scope has its own field")
}

func TestAProjectWithNoPoliciesGivesAnEmptyList(t *testing.T) {
	org := newOrganization(t, newRuntime(t, nil))
	repo := repositoriesOf(t, org)[fakeado.RepoDocsID]

	list := repo.GetPolicies()
	require.NoError(t, list.Error)
	assert.False(t, list.IsNull())
	assert.Empty(t, list.Data)
}

func TestPoliciesTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/policy/configurations")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	list := repo.GetPolicies()
	assert.ErrorIs(t, list.Error, llx.ErrForbidden)
}

func keys[V any](m map[int64]V) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
