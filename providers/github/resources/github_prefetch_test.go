// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// bare runtime with a real resource cache. Neither builder under test reaches
// for the connection, so nothing here talks to GitHub.
func prefetchRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func testRepo(license *github.License) *github.Repository {
	id := int64(1)
	name := "example"
	return &github.Repository{ID: &id, Name: &name, License: license}
}

// Every repository record carries its license, so setting the field means
// GetOrCompute short-circuits and the license() resolver -- one
// Repositories.License call per repository -- never runs.
func TestNewMqlGithubRepository_SetsLicenseFromTheRecord(t *testing.T) {
	runtime := prefetchRuntime()
	key, name, spdx := "mit", "MIT License", "MIT"

	repo, err := newMqlGithubRepository(runtime, testRepo(&github.License{
		Key: &key, Name: &name, SPDXID: &spdx,
	}))
	require.NoError(t, err)

	require.True(t, repo.License.IsSet(), "a set field is what stops the resolver running")
	require.NotNil(t, repo.License.Data)
	assert.Equal(t, "MIT", repo.License.Data.SpdxId.Data)
	assert.Equal(t, "MIT License", repo.License.Data.Name.Data)
}

// The common case, and the one that makes this worth doing: a repository with
// no license reports null straight from the record. Leaving it unset would
// still spend a Repositories.License call each, only to learn there is none --
// on the org measured, 190 of 225 repositories.
func TestNewMqlGithubRepository_AbsentLicenseIsNull(t *testing.T) {
	runtime := prefetchRuntime()

	repo, err := newMqlGithubRepository(runtime, testRepo(nil))
	require.NoError(t, err)

	require.True(t, repo.License.IsSet(), "set, so the resolver does not run")
	assert.True(t, repo.License.State&plugin.StateIsNull != 0, "and explicitly null")
	assert.Nil(t, repo.License.Data)
}

// CreateResource hands back the already-cached instance for a repository some
// other listing has built, so a second record must not overwrite what the
// first one resolved.
func TestNewMqlGithubRepository_FirstLicenseWins(t *testing.T) {
	runtime := prefetchRuntime()
	key, name, spdx := "mit", "MIT License", "MIT"

	first, err := newMqlGithubRepository(runtime, testRepo(&github.License{
		Key: &key, Name: &name, SPDXID: &spdx,
	}))
	require.NoError(t, err)

	otherKey, otherName, otherSpdx := "apache-2.0", "Apache License 2.0", "Apache-2.0"
	second, err := newMqlGithubRepository(runtime, testRepo(&github.License{
		Key: &otherKey, Name: &otherName, SPDXID: &otherSpdx,
	}))
	require.NoError(t, err)

	assert.Same(t, first, second, "same id, so the cached instance comes back")
	assert.Equal(t, "MIT", second.License.Data.SpdxId.Data)
}

// The repository a deploy key was read from is the resource the caller is
// already standing on. Handing it over means repository() -- one
// Repositories.Get per key, repeated for every key on the same repository --
// never runs.
func TestNewMqlDeployKey_TakesTheRepositoryFromItsCaller(t *testing.T) {
	runtime := prefetchRuntime()

	repo, err := newMqlGithubRepository(runtime, testRepo(nil))
	require.NoError(t, err)

	id := int64(7)
	title := "deploy"
	dk, err := newMqlDeployKey(runtime, &github.Key{ID: &id, Title: &title}, repo, "acme", "example")
	require.NoError(t, err)

	require.True(t, dk.Repository.IsSet())
	assert.Same(t, repo, dk.Repository.Data, "must hand back the caller's repository, not refetch it")
}

// A caller without the repository keeps the old behaviour: the field stays
// unset so repository() can fetch it.
func TestNewMqlDeployKey_WithoutARepositoryFallsBack(t *testing.T) {
	runtime := prefetchRuntime()

	id := int64(8)
	dk, err := newMqlDeployKey(runtime, &github.Key{ID: &id}, nil, "acme", "example")
	require.NoError(t, err)

	assert.False(t, dk.Repository.IsSet(), "unset leaves the resolver free to fetch")
	assert.Equal(t, "acme", dk.cacheRepoOwner)
	assert.Equal(t, "example", dk.cacheRepoName)
}

// No repository and no owner/name is a genuine empty state, and must still be
// reported as null rather than left for a resolver that cannot answer.
func TestNewMqlDeployKey_NoRepositoryReferenceIsNull(t *testing.T) {
	runtime := prefetchRuntime()

	id := int64(9)
	dk, err := newMqlDeployKey(runtime, &github.Key{ID: &id}, nil, "", "")
	require.NoError(t, err)

	assert.True(t, dk.Repository.IsSet())
	assert.True(t, dk.Repository.State&plugin.StateIsNull != 0, "should be explicitly null")
	assert.Nil(t, dk.Repository.Data)
}
