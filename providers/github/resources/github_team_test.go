// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Synthetic: a team built from a listing that reports the parent resolves it
// from that listing. The bare runtime has no connection, so falling through
// to the team detail endpoint fails the test.
func TestTeamParentFromListing(t *testing.T) {
	runtime := prefetchRuntime()
	parentTeam := &github.Team{ID: github.Ptr(int64(1)), Name: github.Ptr("platform"), Slug: github.Ptr("platform")}

	child, err := newMqlGithubTeam(runtime, &github.Team{
		ID:                  github.Ptr(int64(2)),
		Name:                github.Ptr("platform-sre"),
		NotificationSetting: github.Ptr("notifications_enabled"),
		Parent:              parentTeam,
	}, llx.NilData, true)
	require.NoError(t, err)
	assert.Equal(t, "notifications_enabled", child.NotificationSetting.Data)

	parent, err := child.parent()
	require.NoError(t, err)
	require.NotNil(t, parent)
	assert.Equal(t, int64(1), parent.Id.Data)
	assert.Equal(t, "platform", parent.Name.Data)

	top, err := newMqlGithubTeam(runtime, &github.Team{ID: github.Ptr(int64(3)), Name: github.Ptr("top")}, llx.NilData, true)
	require.NoError(t, err)
	none, err := top.parent()
	require.NoError(t, err)
	assert.Nil(t, none)
	assert.True(t, top.Parent.IsNull(), "a top-level team has a null parent")
}

// Synthetic: a team first built without parent information picks it up when
// a later listing reports it.
func TestTeamParentKnownUpgrades(t *testing.T) {
	runtime := prefetchRuntime()
	team := &github.Team{ID: github.Ptr(int64(4)), Name: github.Ptr("sec")}

	first, err := newMqlGithubTeam(runtime, team, llx.NilData, false)
	require.NoError(t, err)
	assert.False(t, first.parentKnown)

	withParent := *team
	withParent.Parent = &github.Team{ID: github.Ptr(int64(9))}
	second, err := newMqlGithubTeam(runtime, &withParent, llx.NilData, true)
	require.NoError(t, err)
	assert.Same(t, first, second)
	assert.True(t, second.parentKnown)
	require.NotNil(t, second.cacheParent)
	assert.Equal(t, int64(9), second.cacheParent.GetID())
}
