// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The runtime caches resources under resourceName + "\x00" + __id, and
// CreateResource returns the *cached* instance on a key hit — discarding the
// data it was just handed. Any child resource whose GitLab identifier is only
// unique within its parent therefore has to carry the parent in its key, or a
// query that walks several parents at once (gitlab.group.projects { ... })
// silently reports the first parent's data for all of them.
//
// These tests pin that property for the id builders. They are cheap and they
// are exactly what was missing when the collisions shipped.

func TestScopedIDsDistinguishParents(t *testing.T) {
	t.Run("same child value under different projects", func(t *testing.T) {
		a := projectScopedID("gitlab.project.protectedBranch", 1, "main")
		b := projectScopedID("gitlab.project.protectedBranch", 2, "main")
		assert.NotEqual(t, a, b, "a protected branch named main must not alias across projects")
	})

	t.Run("same variable key and scope under different projects", func(t *testing.T) {
		a := projectScopedID("gitlab.project.variable", 1, "AWS_SECRET_ACCESS_KEY", "*")
		b := projectScopedID("gitlab.project.variable", 2, "AWS_SECRET_ACCESS_KEY", "*")
		assert.NotEqual(t, a, b)
	})

	t.Run("same release tag under different projects", func(t *testing.T) {
		assert.NotEqual(t,
			projectScopedID("gitlab.project.release", 1, "v1.0.0"),
			projectScopedID("gitlab.project.release", 2, "v1.0.0"))
	})

	t.Run("same file path under different projects", func(t *testing.T) {
		assert.NotEqual(t,
			projectScopedID("gitlab.project.file", 1, "main", "README.md"),
			projectScopedID("gitlab.project.file", 2, "main", "README.md"))
	})

	t.Run("same file path at different refs", func(t *testing.T) {
		assert.NotEqual(t,
			projectScopedID("gitlab.project.file", 1, "main", "README.md"),
			projectScopedID("gitlab.project.file", 1, "develop", "README.md"),
			"content() reads the ref, so two refs are two resources")
	})

	t.Run("same user in different groups and projects", func(t *testing.T) {
		// GroupMember.ID / ProjectMember.ID is the *user* id, so the same
		// person yields the same value in every membership they hold.
		// The key also has to name the *kind* of parent: gitlab.member is
		// built from both the group and the project path, so a group with id
		// 10 and a project with id 10 would otherwise share a key.
		inGroup := groupScopedID("gitlab.member/group", 10, "1234")
		inOtherGroup := groupScopedID("gitlab.member/group", 20, "1234")
		inProject := projectScopedID("gitlab.member/project", 10, "1234")

		assert.NotEqual(t, inGroup, inOtherGroup)
		assert.NotEqual(t, inGroup, inProject,
			"a group membership and a project membership are different grants")
	})

	t.Run("same SAML provider and group name under different groups", func(t *testing.T) {
		assert.NotEqual(t,
			groupScopedID("gitlab.group.samlGroupLink", 1, "saml", "developers"),
			groupScopedID("gitlab.group.samlGroupLink", 2, "saml", "developers"))
	})

	t.Run("same identity tuple under different users", func(t *testing.T) {
		// A provider that reports an empty extern_uid would otherwise collapse
		// every user's identity onto one resource.
		assert.NotEqual(t,
			userScopedID("gitlab.user.externalIdentity", 1, "ldapmain", ""),
			userScopedID("gitlab.user.externalIdentity", 2, "ldapmain", ""))
	})

	t.Run("same CI/CD credential id under different projects", func(t *testing.T) {
		// Trigger tokens, schedules, secure files, agents and mirrors are all
		// numbered per project, so id 1 exists in every project on the
		// instance. Without the project in the key, scanning a group would
		// report the first project's credentials for all of them.
		for _, resource := range []string{
			"gitlab.project.pipelineTrigger",
			"gitlab.project.pipelineSchedule",
			"gitlab.project.secureFile",
			"gitlab.project.clusterAgent",
			"gitlab.project.remoteMirror",
		} {
			assert.NotEqual(t,
				projectScopedID(resource, 1, "1"),
				projectScopedID(resource, 2, "1"), resource)
		}
	})

	t.Run("same agent token id under different agents", func(t *testing.T) {
		// Agent token ids are unique per agent, not per project, so the agent
		// has to be in the key as well as the project.
		assert.NotEqual(t,
			projectScopedID("gitlab.project.clusterAgent.token", 1, "10", "5"),
			projectScopedID("gitlab.project.clusterAgent.token", 1, "20", "5"))
		assert.NotEqual(t,
			projectScopedID("gitlab.project.clusterAgent.token", 1, "10", "5"),
			projectScopedID("gitlab.project.clusterAgent.token", 2, "10", "5"))
	})

	t.Run("same identity record under different groups", func(t *testing.T) {
		// Enterprise credentials, service accounts, SSH authorities and access
		// requests are all listed per group. A user who belongs to two groups
		// yields the same token and key ids in both listings.
		for _, resource := range []string{
			"gitlab.group.enterpriseAccessToken",
			"gitlab.group.enterpriseSshKey",
			"gitlab.group.serviceAccount",
			"gitlab.group.sshCertificate",
			"gitlab.group.accessRequest",
		} {
			assert.NotEqual(t,
				groupScopedID(resource, 1, "1"),
				groupScopedID(resource, 2, "1"), resource)
		}
	})

	t.Run("SCIM identity keys on the user, not just the extern uid", func(t *testing.T) {
		// A provider reporting an empty external_uid would otherwise collapse
		// every member's identity onto a single resource.
		assert.NotEqual(t,
			groupScopedID("gitlab.group.scimIdentity", 1, "10", ""),
			groupScopedID("gitlab.group.scimIdentity", 1, "20", ""))
		assert.NotEqual(t,
			groupScopedID("gitlab.group.scimIdentity", 1, "10", "u1"),
			groupScopedID("gitlab.group.scimIdentity", 2, "10", "u1"))
	})

	t.Run("a group request and a project request are different grants", func(t *testing.T) {
		// AccessRequest.ID is the *user* id, so the same person asking to join
		// group 10 and project 10 would otherwise share a key.
		assert.NotEqual(t,
			groupScopedID("gitlab.group.accessRequest", 10, "1234"),
			projectScopedID("gitlab.project.accessRequest", 10, "1234"))
	})

	t.Run("singleton children still differ per parent", func(t *testing.T) {
		// containerExpirationPolicy, approvalSetting and codeowners have no
		// child key at all — the parent id is the only thing separating them.
		for _, resource := range []string{
			"gitlab.project.containerExpirationPolicy",
			"gitlab.project.approvalSetting",
			"gitlab.project.codeowners",
		} {
			assert.NotEqual(t, projectScopedID(resource, 1), projectScopedID(resource, 2), resource)
			assert.NotEmpty(t, projectScopedID(resource, 1), resource)
		}
	})
}

func TestScopedIDsAreStable(t *testing.T) {
	// The same inputs must always produce the same key, or resources stop
	// being shared across a scan and asset continuity breaks between runs.
	assert.Equal(t,
		projectScopedID("gitlab.project.release", 42, "v1.0.0"),
		projectScopedID("gitlab.project.release", 42, "v1.0.0"))

	assert.Equal(t, "gitlab.project.release/42/v1.0.0",
		projectScopedID("gitlab.project.release", 42, "v1.0.0"))
	assert.Equal(t, "gitlab.project.approvalSetting/42",
		projectScopedID("gitlab.project.approvalSetting", 42))
}

func TestMapAccessLevelToRole(t *testing.T) {
	// Every access level GitLab actually issues must map to a name. Reporting
	// "Unknown" for 60 made an instance admin indistinguishable from the
	// no-access user at 0.
	tests := []struct {
		accessLevel int
		want        string
	}{
		{0, "No access"},
		{5, "Minimal Access"},
		{10, "Guest"},
		{15, "Planner"},
		{20, "Reporter"},
		{30, "Developer"},
		{40, "Maintainer"},
		{50, "Owner"},
		{60, "Admin"},
		// genuinely unmapped values still fall through
		{7, "Unknown"},
		{-1, "Unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, mapAccessLevelToRole(tt.accessLevel), "accessLevel=%d", tt.accessLevel)
	}

	t.Run("distinct levels get distinct names", func(t *testing.T) {
		seen := map[string]int{}
		for _, level := range []int{0, 5, 10, 15, 20, 30, 40, 50, 60} {
			role := mapAccessLevelToRole(level)
			require.NotEqual(t, "Unknown", role, "level %d must be mapped", level)
			if prev, ok := seen[role]; ok {
				t.Fatalf("levels %d and %d both map to %q", prev, level, role)
			}
			seen[role] = level
		}
	})
}
