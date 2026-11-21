// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shaped like GET /repos/{owner}/{repo}/rules/branches/{branch} for a default
// branch two rulesets target: an organization ruleset requiring one approval
// and blocking force pushes, and a repository ruleset requiring two approvals,
// code owner review and a status check.
const branchRulesResponse = `[
  {"type": "pull_request", "ruleset_source_type": "Organization", "ruleset_source": "acme", "ruleset_id": 11,
   "parameters": {"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": true, "require_code_owner_review": false, "require_last_push_approval": false, "required_review_thread_resolution": false}},
  {"type": "non_fast_forward", "ruleset_source_type": "Organization", "ruleset_source": "acme", "ruleset_id": 11},
  {"type": "pull_request", "ruleset_source_type": "Repository", "ruleset_source": "acme/web", "ruleset_id": 42,
   "parameters": {"required_approving_review_count": 2, "dismiss_stale_reviews_on_push": false, "require_code_owner_review": true, "require_last_push_approval": false, "required_review_thread_resolution": true}},
  {"type": "required_status_checks", "ruleset_source_type": "Repository", "ruleset_source": "acme/web", "ruleset_id": 42,
   "parameters": {"strict_required_status_checks_policy": true, "required_status_checks": [{"context": "test"}, {"context": "build"}, {"context": "test"}]}},
  {"type": "deletion", "ruleset_source_type": "Repository", "ruleset_source": "acme/web", "ruleset_id": 42}
]`

func TestSummarizeBranchRules(t *testing.T) {
	var rules github.BranchRules
	require.NoError(t, json.Unmarshal([]byte(branchRulesResponse), &rules))
	s := summarizeBranchRules(&rules)

	assert.True(t, s.requiresPullRequest)
	// The strictest ruleset's approval count.
	assert.Equal(t, int64(2), s.requiredApprovingReviewCount)
	assert.True(t, s.requireCodeOwnerReview)
	assert.True(t, s.dismissStaleReviewsOnPush)
	assert.True(t, s.requiredReviewThreadResolution)
	assert.False(t, s.requireLastPushApproval)
	assert.True(t, s.requiresStatusChecks)
	assert.Equal(t, []string{"build", "test"}, s.requiredStatusChecks)
	assert.True(t, s.blocksForcePushes)
	assert.True(t, s.blocksDeletions)
	assert.False(t, s.requiresSignatures)
	assert.False(t, s.requiresLinearHistory)
	assert.False(t, s.restrictsUpdates)
	assert.Equal(t, []int64{11, 42}, s.rulesetIDs)
}

func TestSummarizeBranchRulesWithoutRules(t *testing.T) {
	var rules github.BranchRules
	require.NoError(t, json.Unmarshal([]byte(`[]`), &rules))
	s := summarizeBranchRules(&rules)
	assert.False(t, s.requiresPullRequest)
	assert.Zero(t, s.requiredApprovingReviewCount)
	assert.Empty(t, s.rulesetIDs)
	assert.Equal(t, branchRulesSummary{}, summarizeBranchRules(nil))
}
