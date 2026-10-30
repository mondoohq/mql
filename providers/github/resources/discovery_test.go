// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/github/connection"
)

func TestReposFilter_Include(t *testing.T) {
	reposFilter := NewReposFilter(&inventory.Config{
		Options: map[string]string{
			connection.OPTION_REPOS: "repo1,repo2",
		},
	})
	assert.False(t, reposFilter.skipRepo("repo1"))
	assert.False(t, reposFilter.skipRepo("repo2"))
	assert.True(t, reposFilter.skipRepo("repo3"))
}

func TestReposFilter_Exclude(t *testing.T) {
	reposFilter := NewReposFilter(&inventory.Config{
		Options: map[string]string{
			connection.OPTION_REPOS_EXCLUDE: "repo1,repo2",
		},
	})
	assert.True(t, reposFilter.skipRepo("repo1"))
	assert.True(t, reposFilter.skipRepo("repo2"))
	assert.False(t, reposFilter.skipRepo("repo3"))
}

func TestReposFilter_Both(t *testing.T) {
	reposFilter := NewReposFilter(&inventory.Config{
		Options: map[string]string{
			connection.OPTION_REPOS:         "repo3,repo1",
			connection.OPTION_REPOS_EXCLUDE: "repo1,repo2",
		},
	})
	assert.False(t, reposFilter.skipRepo("repo1")) // include takes precedence
	assert.True(t, reposFilter.skipRepo("repo2"))
	assert.False(t, reposFilter.skipRepo("repo3"))
}

func TestHandleTargets(t *testing.T) {
	t.Run("all expands to repos, users, and the cheap per-repo IaC targets", func(t *testing.T) {
		// The clone-per-match IaC targets (cloudformation, dockerfiles, bicep,
		// helm, kustomize) are intentionally excluded from `all` and only run
		// on an explicit --discover <type>.
		got := handleTargets([]string{connection.DiscoveryAll})
		assert.Equal(t, []string{
			connection.DiscoveryRepos,
			connection.DiscoveryUsers,
			connection.DiscoveryTerraform,
			connection.DiscoveryK8sManifests,
		}, got)
	})

	t.Run("all wins even when mixed with explicit targets", func(t *testing.T) {
		got := handleTargets([]string{connection.DiscoveryRepos, connection.DiscoveryAll})
		assert.Equal(t, []string{
			connection.DiscoveryRepos,
			connection.DiscoveryUsers,
			connection.DiscoveryTerraform,
			connection.DiscoveryK8sManifests,
		}, got)
	})

	t.Run("opt-in IaC targets pass through unchanged", func(t *testing.T) {
		in := []string{
			connection.DiscoveryCloudformation,
			connection.DiscoveryDockerfiles,
			connection.DiscoveryBicep,
			connection.DiscoveryHelm,
			connection.DiscoveryKustomize,
		}
		assert.Equal(t, in, handleTargets(in))
	})

	t.Run("explicit targets pass through unchanged", func(t *testing.T) {
		in := []string{connection.DiscoveryRepos, connection.DiscoveryUsers}
		assert.Equal(t, in, handleTargets(in))
	})

	t.Run("empty stays empty", func(t *testing.T) {
		assert.Empty(t, handleTargets([]string{}))
	})
}

func TestDiscoverUserRepos(t *testing.T) {
	conf := func(opts map[string]string) *inventory.Config {
		return &inventory.Config{Options: opts}
	}

	t.Run("user scope with auto discovery fans out to the account's repos", func(t *testing.T) {
		// the server sends discover=auto for GitHub integrations, including
		// personal-account app installs (user scope)
		assert.True(t, discoverUserRepos(
			conf(map[string]string{"user": "some-user"}),
			[]string{connection.DiscoveryAuto},
		))
	})

	t.Run("repos and all targets fan out too", func(t *testing.T) {
		assert.True(t, discoverUserRepos(
			conf(map[string]string{"user": "some-user"}),
			[]string{connection.DiscoveryRepos},
		))
		assert.True(t, discoverUserRepos(
			conf(map[string]string{"user": "some-user"}),
			[]string{connection.DiscoveryAll},
		))
	})

	t.Run("an explicit repository never fans out", func(t *testing.T) {
		// a single-repo scan must scan exactly the one repo
		assert.False(t, discoverUserRepos(
			conf(map[string]string{"owner": "some-user", "repository": "one-repo"}),
			[]string{connection.DiscoveryAuto},
		))
	})
}

// A single-repo scan carries owner+repository; "owner" is that repo's namespace,
// not a user to discover. Treating it as a user emitted a phantom user asset for
// the owner (empty-named when the owner is an organization).
func TestUserDiscoveryTarget(t *testing.T) {
	conf := func(opts map[string]string) *inventory.Config {
		return &inventory.Config{Options: opts}
	}

	t.Run("explicit user scope discovers that user", func(t *testing.T) {
		assert.Equal(t, "some-user",
			userDiscoveryTarget(conf(map[string]string{"user": "some-user"})))
	})

	t.Run("bare owner (no repository) is a user shortcut", func(t *testing.T) {
		assert.Equal(t, "some-user",
			userDiscoveryTarget(conf(map[string]string{"owner": "some-user"})))
	})

	t.Run("owner with a repository is NOT a user scope", func(t *testing.T) {
		assert.Empty(t, userDiscoveryTarget(
			conf(map[string]string{"owner": "some-org", "repository": "one-repo"})))
	})

	t.Run("nothing to discover", func(t *testing.T) {
		assert.Empty(t, userDiscoveryTarget(conf(map[string]string{})))
	})

	t.Run("no repo-ish discovery target means no fan-out", func(t *testing.T) {
		assert.False(t, discoverUserRepos(
			conf(map[string]string{"user": "some-user"}),
			[]string{connection.DiscoveryUsers},
		))
		assert.False(t, discoverUserRepos(
			conf(map[string]string{"user": "some-user"}),
			nil,
		))
	})
}

// `--discover none` must mean none. The repository and user assets were
// appended unconditionally, so a single-repo scan produced three assets (the
// connection's own asset, the repository again, and the owner account) and ran
// every query three times.
func TestDiscoverRepoAsset(t *testing.T) {
	t.Run("the default auto target emits the repository asset", func(t *testing.T) {
		assert.True(t, discoverRepoAsset([]string{connection.DiscoveryAuto}))
	})

	t.Run("repos and all emit it too", func(t *testing.T) {
		assert.True(t, discoverRepoAsset([]string{connection.DiscoveryRepos}))
		assert.True(t, discoverRepoAsset(handleTargets([]string{connection.DiscoveryAll})))
	})

	t.Run("none emits nothing", func(t *testing.T) {
		assert.False(t, discoverRepoAsset([]string{"none"}))
		assert.False(t, discoverRepoAsset(nil))
	})

	t.Run("an unrelated target does not emit it", func(t *testing.T) {
		assert.False(t, discoverRepoAsset([]string{connection.DiscoveryUsers}))
	})
}

func TestDiscoverUserAsset(t *testing.T) {
	t.Run("the default auto target emits the user asset", func(t *testing.T) {
		assert.True(t, discoverUserAsset([]string{connection.DiscoveryAuto}))
	})

	t.Run("users and all emit it too", func(t *testing.T) {
		assert.True(t, discoverUserAsset([]string{connection.DiscoveryUsers}))
		assert.True(t, discoverUserAsset(handleTargets([]string{connection.DiscoveryAll})))
	})

	t.Run("none emits nothing", func(t *testing.T) {
		assert.False(t, discoverUserAsset([]string{"none"}))
		assert.False(t, discoverUserAsset(nil))
	})

	t.Run("an unrelated target does not emit it", func(t *testing.T) {
		assert.False(t, discoverUserAsset([]string{connection.DiscoveryOrganization}))
	})
}
