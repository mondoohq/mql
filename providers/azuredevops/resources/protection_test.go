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

// branchOf is one branch of one fixture repository, read through a fresh
// runtime with the fake's options.
func branchOf(t *testing.T, repoID, name string) *mqlAzuredevopsBranch {
	t.Helper()
	org := newOrganization(t, newRuntime(t, nil))
	b := branchesOf(t, repositoriesOf(t, org)[repoID])[name]
	require.NotNil(t, b, name)
	return b
}

func rulesOf(t *testing.T, b *mqlAzuredevopsBranch) *mqlAzuredevopsBranchProtection {
	t.Helper()
	rules := b.GetProtectionRules()
	require.NoError(t, rules.Error)
	require.NotNil(t, rules.Data)
	return rules.Data
}

func policyIDs(t *testing.T, rules *mqlAzuredevopsBranchProtection) []int64 {
	t.Helper()
	var out []int64
	for _, p := range rules.Policies.Data {
		out = append(out, p.(*mqlAzuredevopsPolicy).Id.Data)
	}
	return out
}

func TestTheWeakDefaultBranchNeedsOneReviewAndNothingElse(t *testing.T) {
	b := branchOf(t, fakeado.RepoIacID, "main")

	protected := b.GetIsProtected()
	require.NoError(t, protected.Error)
	assert.True(t, protected.Data)

	rules := rulesOf(t, b)
	assert.Equal(t, "refs/heads/main", rules.RefName.Data)
	assert.True(t, rules.RequiredPullRequestReviewsEnabled.Data)
	assert.Equal(t, int64(1), rules.RequiredApprovingReviewCount.Data)
	assert.False(t, rules.RequireCodeOwnerReviews.Data)
	assert.False(t, rules.RequiredConversationResolutionEnabled.Data, "the project-wide comment policy is disabled")
	assert.False(t, rules.RequiredStatusChecksEnabled.Data, "the build policy only warns")
	assert.Equal(t, []int64{11}, policyIDs(t, rules))
}

func TestTheWeakReleaseBranchIsNotProtected(t *testing.T) {
	b := branchOf(t, fakeado.RepoIacID, "release/1.0")

	protected := b.GetIsProtected()
	require.NoError(t, protected.Error)
	assert.False(t, protected.Data, "its only policy is deleted")

	rules := rulesOf(t, b)
	assert.False(t, rules.RequiredPullRequestReviewsEnabled.Data)
	assert.Equal(t, int64(0), rules.RequiredApprovingReviewCount.Data)
	assert.Empty(t, rules.Policies.Data)
}

func TestTheStrongDefaultBranchHasEveryPolicy(t *testing.T) {
	rules := rulesOf(t, branchOf(t, fakeado.RepoAppID, "main"))

	assert.True(t, rules.RequiredPullRequestReviewsEnabled.Data)
	assert.Equal(t, int64(2), rules.RequiredApprovingReviewCount.Data)
	assert.True(t, rules.RequireCodeOwnerReviews.Data)
	assert.True(t, rules.RequiredConversationResolutionEnabled.Data)
	assert.True(t, rules.RequiredStatusChecksEnabled.Data)
	assert.ElementsMatch(t, []int64{21, 22, 23, 25}, policyIDs(t, rules))
}

func TestAPrefixPolicyProtectsTheReleaseBranch(t *testing.T) {
	b := branchOf(t, fakeado.RepoAppID, "release/1.0")

	assert.True(t, b.GetIsProtected().Data)
	rules := rulesOf(t, b)
	assert.Equal(t, int64(2), rules.RequiredApprovingReviewCount.Data)
	assert.Equal(t, []int64{24}, policyIDs(t, rules))
}

func TestProtectionTheCredentialCannotReadIsForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/policy/configurations")
	b := branchesOf(t, repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID])["main"]
	require.NotNil(t, b)

	protected := b.GetIsProtected()
	assert.ErrorIs(t, protected.Error, llx.ErrForbidden)

	rules := b.GetProtectionRules()
	assert.ErrorIs(t, rules.Error, llx.ErrForbidden)
}

func TestSummarizeTakesTheHighestReviewCount(t *testing.T) {
	reviewers := func(n float64) connection.PolicyConfiguration {
		return connection.PolicyConfiguration{
			Type:     connection.PolicyType{ID: connection.PolicyTypeMinimumReviewers},
			Settings: connection.PolicySettings{All: map[string]any{"minimumApproverCount": n}},
		}
	}
	assert.Equal(t, int64(3), summarize([]connection.PolicyConfiguration{reviewers(1), reviewers(3), reviewers(2)}).reviewCount)
	assert.Equal(t, int64(0), summarize(nil).reviewCount)
}

func TestSummarizeReadsTheTypeIDInAnyLetterCase(t *testing.T) {
	upper := connection.PolicyConfiguration{Type: connection.PolicyType{ID: "C6A1889D-B943-4856-B76F-9E46BB6B0DF2"}}
	assert.True(t, summarize([]connection.PolicyConfiguration{upper}).commentsResolve)
}
