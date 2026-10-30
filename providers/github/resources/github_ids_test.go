// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every builder here keys a resource that is only unique within a repository,
// an owner, or a runner scope. The tests below pin the property that matters:
// two things that can legitimately coexist in one scan must not share a key.

func TestCommitAuthorID(t *testing.T) {
	sha := "7730d2707fdb6422f335fddc944ab169d45f3aa5"

	assert.Equal(t, "git.commitAuthor/"+sha+"/author", commitAuthorID(sha, "author"))
	assert.NotEqual(t, commitAuthorID(sha, "author"), commitAuthorID(sha, "committer"),
		"a commit's author and committer must not share a cache key")
}

func TestCollaboratorID(t *testing.T) {
	assert.Equal(t, "github.collaborator/mondoohq/cnquery/42",
		collaboratorID("mondoohq", "cnquery", 42))

	assert.NotEqual(t,
		collaboratorID("mondoohq", "cnquery", 42),
		collaboratorID("mondoohq", "cnspec", 42),
		"the same user on two repositories must not share a cache key")
}

func TestAlertID(t *testing.T) {
	assert.Equal(t, "github.dependabotAlert/mondoohq/cnquery/1",
		alertID("github.dependabotAlert", "mondoohq", "cnquery", 1))

	// Alert numbers restart at 1 in every repository.
	assert.NotEqual(t,
		alertID("github.dependabotAlert", "mondoohq", "cnquery", 1),
		alertID("github.dependabotAlert", "mondoohq", "cnspec", 1))

	// Different alert kinds share the number space too.
	assert.NotEqual(t,
		alertID("github.dependabotAlert", "mondoohq", "cnquery", 1),
		alertID("github.codeScanningAlert", "mondoohq", "cnquery", 1))
}

func TestBranchID(t *testing.T) {
	assert.Equal(t, "github.branch/mondoohq/cnquery/main", branchID("mondoohq", "cnquery", "main"))

	// A fork keeps the repository name of its upstream.
	assert.NotEqual(t,
		branchID("mondoohq", "cnquery", "main"),
		branchID("someone-else", "cnquery", "main"))
}

func TestCodeownersRuleID(t *testing.T) {
	assert.Equal(t, "github.codeowners.rule/mondoohq/cnquery/*/1",
		codeownersRuleID("mondoohq", "cnquery", "*", 1))

	// "* @org/team" on line 1 is near-universal across repositories.
	assert.NotEqual(t,
		codeownersRuleID("mondoohq", "cnquery", "*", 1),
		codeownersRuleID("mondoohq", "cnspec", "*", 1))
}

func TestRunnerID(t *testing.T) {
	assert.Equal(t, "github.runner/orgs/mondoohq/7", runnerID("orgs/mondoohq", "7"))

	// Organization and repository runners are numbered independently.
	assert.NotEqual(t,
		runnerID("orgs/mondoohq", "7"),
		runnerID("repos/mondoohq/cnquery", "7"))
}

func TestRunnerKey(t *testing.T) {
	id := func(v int64) *int64 { return &v }
	name := func(v string) *string { return &v }

	assert.Equal(t, "7", runnerKey(&ghRunnerExt{ID: id(7), Name: name("builder-1")}, 0))

	// An absent id falls back to the name, which is unique within the scope.
	// Keying both on the id's zero value would collapse them onto one resource.
	assert.NotEqual(t,
		runnerKey(&ghRunnerExt{Name: name("builder-1")}, 0),
		runnerKey(&ghRunnerExt{Name: name("builder-2")}, 1))

	// With neither an id nor a name, the listing position keeps them distinct.
	assert.NotEqual(t,
		runnerKey(&ghRunnerExt{}, 0),
		runnerKey(&ghRunnerExt{}, 1))

	// A name-keyed runner must not collide with the runner whose id is that name.
	assert.NotEqual(t,
		runnerKey(&ghRunnerExt{Name: name("7")}, 0),
		runnerKey(&ghRunnerExt{ID: id(7)}, 1))
}

func TestOrganizationMembershipID(t *testing.T) {
	assert.Equal(t, "github.organization.membership/mondoohq/alice",
		organizationMembershipID("mondoohq", "alice"))

	// One account can be a member of more than one organization in a scan.
	assert.NotEqual(t,
		organizationMembershipID("mondoohq", "alice"),
		organizationMembershipID("other-org", "alice"))
}

func TestOrganizationInvitationID(t *testing.T) {
	assert.Equal(t, "github.organization.invitation/mondoohq/42",
		organizationInvitationID("mondoohq", 42))

	assert.NotEqual(t,
		organizationInvitationID("mondoohq", 42),
		organizationInvitationID("other-org", 42))
}

func TestRepositoryTeamID(t *testing.T) {
	assert.Equal(t, "github.repository.team/mondoohq/cnquery/platform",
		repositoryTeamID("mondoohq/cnquery", "platform"))

	// The same team almost always holds a grant on many repositories, and the
	// permission it confers differs per repository. Keying on the slug alone
	// would collapse them onto one resource and report the first permission
	// found for every repository.
	assert.NotEqual(t,
		repositoryTeamID("mondoohq/cnquery", "platform"),
		repositoryTeamID("mondoohq/cnspec", "platform"))
}

func TestRunnerGroupID(t *testing.T) {
	assert.Equal(t, "github.organization.runnerGroup/mondoohq/1",
		runnerGroupID("mondoohq", 1))

	// Runner groups are numbered per organization, and every organization has
	// a "Default" group with id 1.
	assert.NotEqual(t,
		runnerGroupID("mondoohq", 1),
		runnerGroupID("other-org", 1))
}

func TestRunnerLabelID(t *testing.T) {
	scope := "orgs/mondoohq"
	name := func(v string) *string { return &v }

	// Read-only labels reuse the same ids on every runner, so the key has to
	// carry the runner as well as the label name.
	assert.NotEqual(t,
		runnerLabelID(scope, "1", "self-hosted"),
		runnerLabelID(scope, "2", "self-hosted"))

	// The API omits the id for some labels; distinct names must still differ.
	assert.NotEqual(t,
		runnerLabelID(scope, "1", "gpu"),
		runnerLabelID(scope, "1", "arm64"))

	// Labels on two id-less runners stay separate, since the runner key does.
	assert.NotEqual(t,
		runnerLabelID(scope, runnerKey(&ghRunnerExt{Name: name("builder-1")}, 0), "self-hosted"),
		runnerLabelID(scope, runnerKey(&ghRunnerExt{Name: name("builder-2")}, 1), "self-hosted"))
}
