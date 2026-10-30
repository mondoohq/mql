// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every expectation below is written as a literal, never read back from the
// floor constants or the plan-name set the implementation reads, so moving a
// floor or dropping a plan name fails a test instead of moving both sides
// together.

func TestCompareGhesVersions(t *testing.T) {
	// The case that matters: release numbers are not lexically ordered. A
	// string comparison puts "3.9" above "3.13", which would report a 2023
	// installation as carrying features it does not have.
	assert.Equal(t, -1, compareGhesVersions("3.9", "3.13"))
	assert.Equal(t, 1, compareGhesVersions("3.13", "3.9"))

	assert.Equal(t, 0, compareGhesVersions("3.16", "3.16"))
	assert.Equal(t, -1, compareGhesVersions("3.15.4", "3.16"))
	assert.Equal(t, 1, compareGhesVersions("3.16.1", "3.16"))

	// A missing component counts as zero, so a floor written without a patch
	// matches the release that reports one.
	assert.Equal(t, 0, compareGhesVersions("3.16.0", "3.16"))

	// Parsing stops at the first non-numeric component, so a pre-release build
	// compares as the release it precedes rather than as an empty version.
	assert.Equal(t, 0, compareGhesVersions("3.17.0.rc1", "3.17"))
	assert.Equal(t, 1, compareGhesVersions("3.17.0.rc1", "3.16"))

	// A version that parses to nothing must not sort above a real release.
	assert.Equal(t, -1, compareGhesVersions("unknown", "3.16"))
}

func TestGithubFeaturesOnGitHubDotCom(t *testing.T) {
	enterprise := githubFeatures("enterprise", "", false)
	require.NotNil(t, enterprise.AuditLog)
	assert.True(t, *enterprise.AuditLog)
	require.NotNil(t, enterprise.AuditLogStreaming)
	assert.True(t, *enterprise.AuditLogStreaming)
	require.NotNil(t, enterprise.CustomRoles)
	assert.True(t, *enterprise.CustomRoles)

	// Team is the tier people most often mistake for Enterprise, and it is the
	// tier that makes the audit log come back empty.
	team := githubFeatures("team", "", false)
	require.NotNil(t, team.AuditLog)
	assert.False(t, *team.AuditLog)
	require.NotNil(t, team.SamlSingleSignOn)
	assert.False(t, *team.SamlSingleSignOn)

	free := githubFeatures("free", "", false)
	require.NotNil(t, free.IpAllowList)
	assert.False(t, *free.IpAllowList)

	// Accounts created before GitHub renamed the plan still report the old
	// names, and they carry the same feature set.
	for _, name := range []string{"business", "business_plus"} {
		legacy := githubFeatures(name, "", false)
		require.NotNil(t, legacy.AuditLog, name)
		assert.True(t, *legacy.AuditLog, name)
	}

	// GitHub does not publish the full set of plan names. One it has not
	// published yet must not read as Enterprise.
	unknown := githubFeatures("something-new", "", false)
	require.NotNil(t, unknown.AuditLog)
	assert.False(t, *unknown.AuditLog)
}

func TestGithubFeaturesUnmeasuredReadsNull(t *testing.T) {
	// GitHub serves a plan only to a token with owner access. Without one,
	// nothing was measured, and a false here would state that an Enterprise
	// organization lacks features it pays for.
	noPlan := githubFeatures("", "", false)
	assert.Nil(t, noPlan.AuditLog)
	assert.Nil(t, noPlan.SamlSingleSignOn)
	assert.Nil(t, noPlan.IpAllowList)
	assert.Nil(t, noPlan.CustomRoles)
	assert.Nil(t, noPlan.ApprovedTokens)
	assert.Nil(t, noPlan.AuditLogStreaming)

	// An installation that withholds its release leaves every floor
	// unanswerable, even though it is known to be Enterprise Server.
	noVersion := githubFeatures("", "", true)
	assert.Nil(t, noVersion.AuditLog)
	assert.Nil(t, noVersion.CustomRoles)
	assert.Nil(t, noVersion.AuditLogStreaming)
}

func TestGithubFeaturesOnEnterpriseServer(t *testing.T) {
	// A release below three of the floors and above the other three.
	old := githubFeatures("", "3.11.9", true)
	require.NotNil(t, old.AuditLog)
	assert.True(t, *old.AuditLog, "the audit log predates every supported release")
	require.NotNil(t, old.SamlSingleSignOn)
	assert.True(t, *old.SamlSingleSignOn)
	require.NotNil(t, old.IpAllowList)
	assert.True(t, *old.IpAllowList)
	require.NotNil(t, old.CustomRoles)
	assert.False(t, *old.CustomRoles, "custom organization roles arrived in 3.13")
	require.NotNil(t, old.ApprovedTokens)
	assert.False(t, *old.ApprovedTokens, "token approval arrived in 3.12")
	require.NotNil(t, old.AuditLogStreaming)
	assert.False(t, *old.AuditLogStreaming, "streaming configuration arrived in 3.16")

	// Exactly at a floor the feature is present, which is what separates a
	// correct comparison from one written with a strict inequality.
	atFloor := githubFeatures("", "3.16", true)
	require.NotNil(t, atFloor.AuditLogStreaming)
	assert.True(t, *atFloor.AuditLogStreaming)

	justBelow := githubFeatures("", "3.15.9", true)
	require.NotNil(t, justBelow.AuditLogStreaming)
	assert.False(t, *justBelow.AuditLogStreaming)
	require.NotNil(t, justBelow.ApprovedTokens)
	assert.True(t, *justBelow.ApprovedTokens, "3.15 is above the 3.12 floor")

	// A current release carries everything.
	current := githubFeatures("", "3.20.1", true)
	require.NotNil(t, current.CustomRoles)
	assert.True(t, *current.CustomRoles)
	require.NotNil(t, current.AuditLogStreaming)
	assert.True(t, *current.AuditLogStreaming)

	// An Enterprise Server installation serves no plan, and must not be read as
	// a free account because of it.
	require.NotNil(t, current.AuditLog)
	assert.True(t, *current.AuditLog)
}

func TestGithubFeaturesIgnoresPlanNameCase(t *testing.T) {
	mixed := githubFeatures("Enterprise", "", false)
	require.NotNil(t, mixed.AuditLog)
	assert.True(t, *mixed.AuditLog)
}
