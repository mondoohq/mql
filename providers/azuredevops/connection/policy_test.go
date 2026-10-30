// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestPolicyConfigurationsDecodeTheScopeAndKeepEverySetting(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	policies, err := c.PolicyConfigurations(context.Background(), "scan-test")
	require.NoError(t, err)
	require.Len(t, policies, 9)

	first := policies[0]
	assert.Equal(t, int64(11), first.ID)
	assert.Equal(t, PolicyTypeMinimumReviewers, first.Type.ID)
	assert.True(t, first.Enforced())
	require.Len(t, first.Settings.Scope, 1)
	assert.Equal(t, fakeado.RepoIacID, first.Settings.Scope[0].RepositoryID)
	assert.Equal(t, "refs/heads/main", first.Settings.Scope[0].RefName)
	assert.Equal(t, "Exact", first.Settings.Scope[0].MatchKind)
	assert.Equal(t, float64(1), first.Settings.All["minimumApproverCount"])

	projectWide := policies[8]
	assert.Empty(t, projectWide.Settings.Scope[0].RepositoryID, "a null repositoryId means every repository")
	assert.False(t, projectWide.Enforced(), "a disabled policy is not enforced")
}

func TestPolicyConfigurationsAreFetchedOncePerProject(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	for range 3 {
		_, err := c.PolicyConfigurations(context.Background(), "scan-test")
		require.NoError(t, err)
	}
	_, err := c.PolicyConfigurations(context.Background(), "legacy-apps")
	require.NoError(t, err)

	calls := 0
	for _, r := range srv.Requests() {
		if strings.Contains(r, "/policy/configurations") {
			calls++
		}
	}
	assert.Equal(t, 2, calls, "one call per project")
}

func TestPolicyConfigurationsOfAProjectTheCredentialCannotReadAreForbidden(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	_, err := c.PolicyConfigurations(context.Background(), "locked-down")
	assert.True(t, IsForbidden(err))
}

func TestPolicyScopeCovers(t *testing.T) {
	const repo = "2b000000-0000-4000-8000-000000000001"
	const other = "2b000000-0000-4000-8000-000000000002"
	cases := []struct {
		name          string
		scope         PolicyScope
		ref           string
		defaultBranch string
		want          bool
	}{
		{"exact match", PolicyScope{repo, "refs/heads/main", "Exact"}, "refs/heads/main", "refs/heads/main", true},
		{"exact ignores letter case", PolicyScope{strings.ToUpper(repo), "refs/heads/Main", "exact"}, "refs/heads/main", "", true},
		{"exact is not a prefix", PolicyScope{repo, "refs/heads/main", "Exact"}, "refs/heads/main-old", "", false},
		{"no match kind means exact", PolicyScope{repo, "refs/heads/main", ""}, "refs/heads/main", "", true},
		{"another repository", PolicyScope{other, "refs/heads/main", "Exact"}, "refs/heads/main", "", false},
		{"every repository", PolicyScope{"", "refs/heads/main", "Exact"}, "refs/heads/main", "", true},
		{"prefix", PolicyScope{repo, "refs/heads/release/", "Prefix"}, "refs/heads/release/1.0", "", true},
		{"prefix ignores letter case", PolicyScope{repo, "refs/heads/Release/", "Prefix"}, "refs/heads/release/1.0", "", true},
		{"prefix longer than the ref", PolicyScope{repo, "refs/heads/release/1.0/hotfix", "Prefix"}, "refs/heads/release/1.0", "", false},
		{"default branch", PolicyScope{"", "", "DefaultBranch"}, "refs/heads/main", "refs/heads/main", true},
		{"default branch on another branch", PolicyScope{"", "", "DefaultBranch"}, "refs/heads/release/1.0", "refs/heads/main", false},
		{"default branch of an empty repository", PolicyScope{"", "", "DefaultBranch"}, "refs/heads/main", "", false},
		{"no ref name covers nothing", PolicyScope{repo, "", "Exact"}, "refs/heads/main", "refs/heads/main", false},
		{"no ref name prefix covers nothing", PolicyScope{repo, "", "Prefix"}, "refs/heads/main", "refs/heads/main", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.scope.Covers(repo, tc.ref, tc.defaultBranch))
		})
	}
}

func TestOnlyAnEnabledBlockingLivePolicyIsEnforced(t *testing.T) {
	assert.True(t, PolicyConfiguration{IsEnabled: true, IsBlocking: true}.Enforced())
	assert.False(t, PolicyConfiguration{IsEnabled: false, IsBlocking: true}.Enforced())
	assert.False(t, PolicyConfiguration{IsEnabled: true, IsBlocking: false}.Enforced())
	assert.False(t, PolicyConfiguration{IsEnabled: true, IsBlocking: true, IsDeleted: true}.Enforced())
}
