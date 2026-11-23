// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: reviewer list as GitHub documents it; no target showed this.
func TestBypassReviewersToDicts(t *testing.T) {
	assert.Empty(t, bypassReviewersToDicts(nil), "no delegated bypass reports no reviewers")

	got := bypassReviewersToDicts(&github.SecretScanningDelegatedBypassOptions{
		Reviewers: []*github.BypassReviewer{
			{ReviewerID: 7, ReviewerType: "TEAM"},
			nil,
			{ReviewerID: 9, ReviewerType: "ROLE"},
		},
	})
	assert.Equal(t, []any{
		map[string]any{"reviewerId": int64(7), "reviewerType": "TEAM"},
		map[string]any{"reviewerId": int64(9), "reviewerType": "ROLE"},
	}, got)
}

// Synthetic: defaults response shapes; no target showed these.
func TestDefaultsForNewRepos(t *testing.T) {
	var defaults []*github.CodeSecurityConfigurationWithDefaultForNewRepos
	require.NoError(t, json.Unmarshal([]byte(`[
		{"default_for_new_repos": "public", "configuration": {"id": 1, "name": "a"}},
		{"default_for_new_repos": "private_and_internal", "configuration": {"id": 2, "name": "b"}},
		{"configuration": {"id": 3, "name": "no default"}},
		{"default_for_new_repos": "all"}
	]`), &defaults))

	got := defaultsForNewRepos(defaults)
	assert.Equal(t, map[int64]string{1: "public", 2: "private_and_internal"}, got)
}

// Synthetic: a configuration without the optional option blocks; no target
// showed this.
func TestNewMqlCodeSecurityConfigurationAbsentOptionsAreNull(t *testing.T) {
	var c github.CodeSecurityConfiguration
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": 17, "name": "GitHub recommended", "description": "d",
		"target_type": "global", "enforcement": "enforced",
		"advanced_security": "enabled", "secret_scanning_push_protection": "enabled"
	}`), &c))

	r, err := newMqlCodeSecurityConfiguration(prefetchRuntime(), "o", &c)
	require.NoError(t, err)
	assert.Equal(t, "global", r.TargetType.Data)
	assert.Equal(t, "enabled", r.SecretScanningPushProtection.Data)
	assert.True(t, r.CodeScanningDefaultSetupRunnerType.State&plugin.StateIsNull != 0,
		"runner type is null when the default setup options are absent")
	assert.True(t, r.CodeScanningAllowAdvanced.State&plugin.StateIsNull != 0,
		"allowAdvanced is null, not false, when the code scanning options are absent")
	assert.True(t, r.DependencyGraphAutosubmitActionLabeledRunners.State&plugin.StateIsNull != 0)
	assert.True(t, r.DependabotAlerts.State&plugin.StateIsNull != 0, "an absent feature setting is null, not empty")
	assert.True(t, r.CreatedAt.State&plugin.StateIsNull != 0)
}

// Synthetic: option blocks present; no target showed this.
func TestNewMqlCodeSecurityConfigurationOptions(t *testing.T) {
	var c github.CodeSecurityConfiguration
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": 18, "name": "custom",
		"code_scanning_default_setup_options": {"runner_type": "labeled", "runner_label": "code-scanning"},
		"code_scanning_options": {"allow_advanced": false},
		"dependency_graph_autosubmit_action_options": {"labeled_runners": true},
		"secret_scanning_delegated_bypass_options": {"reviewers": [{"reviewer_id": 4, "reviewer_type": "TEAM"}]}
	}`), &c))

	r, err := newMqlCodeSecurityConfiguration(prefetchRuntime(), "o", &c)
	require.NoError(t, err)
	assert.Equal(t, "labeled", r.CodeScanningDefaultSetupRunnerType.Data)
	assert.Equal(t, "code-scanning", r.CodeScanningDefaultSetupRunnerLabel.Data)
	assert.Equal(t, plugin.StateIsSet, r.CodeScanningAllowAdvanced.State)
	assert.False(t, r.CodeScanningAllowAdvanced.Data)
	assert.True(t, r.DependencyGraphAutosubmitActionLabeledRunners.Data)
	require.Len(t, r.cacheReviewers, 1)
	assert.Equal(t, int64(4), r.cacheReviewers[0].ReviewerID)
	assert.Equal(t, "o", r.cacheOrgLogin)
}

// Synthetic: GitHub's own configurations carry the same id in every
// organization; no target showed this.
func TestCodeSecurityConfigurationIDIsPerOrganization(t *testing.T) {
	assert.NotEqual(t, codeSecurityConfigurationID("a", 17), codeSecurityConfigurationID("b", 17))
}
