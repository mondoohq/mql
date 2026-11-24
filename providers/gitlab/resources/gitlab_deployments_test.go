// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestGroupProtectedEnvironmentsShareTheProjectShape(t *testing.T) {
	// Synthetic: group protected environment access levels and approval rules
	// as the group protected environments API documents them.
	levels := envDeployAccessLevelsToDicts(groupEnvAccessLevels([]*gitlab.GroupEnvironmentAccessDescription{{
		ID:                     7,
		AccessLevel:            gitlab.MaintainerPermissions,
		AccessLevelDescription: "Maintainers",
		UserID:                 3,
		GroupID:                9,
		GroupInheritanceType:   1,
	}}))
	require.Len(t, levels, 1)
	assert.Equal(t, map[string]any{
		"accessLevel":            int64(40),
		"accessLevelDescription": "Maintainers",
		"userId":                 int64(3),
		"groupId":                int64(9),
		"groupInheritanceType":   int64(1),
	}, levels[0])

	rules := envApprovalRulesToDicts(groupEnvApprovalRules([]*gitlab.GroupEnvironmentApprovalRule{{
		ID:                     5,
		UserID:                 0,
		GroupID:                9,
		AccessLevel:            gitlab.DeveloperPermissions,
		AccessLevelDescription: "Developers",
		RequiredApprovalCount:  2,
		GroupInheritanceType:   0,
	}}))
	require.Len(t, rules, 1)
	assert.Equal(t, map[string]any{
		"id":                     int64(5),
		"accessLevel":            int64(30),
		"accessLevelDescription": "Developers",
		"userId":                 int64(0),
		"groupId":                int64(9),
		"requiredApprovalCount":  int64(2),
		"groupInheritanceType":   int64(0),
	}, rules[0])
}

func TestGroupProtectedEnvironmentsSkipNilEntries(t *testing.T) {
	// Synthetic: a nil element in the decoded list.
	assert.Empty(t, envDeployAccessLevelsToDicts(groupEnvAccessLevels([]*gitlab.GroupEnvironmentAccessDescription{nil})))
	assert.Empty(t, envApprovalRulesToDicts(groupEnvApprovalRules([]*gitlab.GroupEnvironmentApprovalRule{nil})))
}
