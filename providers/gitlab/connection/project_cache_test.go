// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestCacheDiscoveredProjects(t *testing.T) {
	t.Cleanup(FlushDiscoveredProjects)
	FlushDiscoveredProjects()

	CacheDiscoveredProjects("https://gitlab.com", []*gitlab.Project{
		{ID: 1, Name: "alpha"},
		{ID: 2, Name: "beta"},
	})

	got := cachedDiscoveredProject("https://gitlab.com", 1)
	assert.NotNil(t, got)
	assert.Equal(t, "alpha", got.Name)

	assert.Nil(t, cachedDiscoveredProject("https://gitlab.com", 99), "an undiscovered project must fall through to a fetch")
}

// Ids are only unique within a GitLab instance, so a self-hosted project 1 must
// not be served for gitlab.com's project 1.
func TestCacheIsScopedToTheInstance(t *testing.T) {
	t.Cleanup(FlushDiscoveredProjects)
	FlushDiscoveredProjects()

	CacheDiscoveredProjects("https://gitlab.com", []*gitlab.Project{{ID: 1, Name: "saas"}})
	CacheDiscoveredProjects("https://git.acme.internal", []*gitlab.Project{{ID: 1, Name: "self-hosted"}})

	assert.Equal(t, "saas", cachedDiscoveredProject("https://gitlab.com", 1).Name)
	assert.Equal(t, "self-hosted", cachedDiscoveredProject("https://git.acme.internal", 1).Name)
	assert.Nil(t, cachedDiscoveredProject("https://other.example", 1))
}

// A listing that returns a nil entry or an id-less project must not poison the
// cache: storing those would make a later lookup return a hollow record instead
// of falling through to a real fetch.
func TestCacheSkipsUnusableEntries(t *testing.T) {
	t.Cleanup(FlushDiscoveredProjects)
	FlushDiscoveredProjects()

	CacheDiscoveredProjects("https://gitlab.com", []*gitlab.Project{nil, {ID: 0, Name: "no id"}, {ID: 7, Name: "good"}})

	assert.Nil(t, cachedDiscoveredProject("https://gitlab.com", 0))
	assert.NotNil(t, cachedDiscoveredProject("https://gitlab.com", 7))
}

func TestCacheIgnoresAnEmptyListing(t *testing.T) {
	t.Cleanup(FlushDiscoveredProjects)
	FlushDiscoveredProjects()

	CacheDiscoveredProjects("https://gitlab.com", nil)
	assert.Nil(t, cachedDiscoveredProject("https://gitlab.com", 1))
}
