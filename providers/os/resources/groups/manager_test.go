// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/groups"
)

func TestManagerDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := groups.ResolveManager(mock)
	require.NoError(t, err)
	groupList, err := mm.List()
	require.NoError(t, err)

	grp := findGroup(groupList, "0")
	assert.Equal(t, "0", grp.ID)
	assert.Equal(t, int64(0), grp.Gid)
	assert.Equal(t, "root", grp.Name)
	assert.Equal(t, []string{"root", "sync", "shutdown", "halt", "operator"}, grp.Members)

	assert.Equal(t, 23, len(groupList))
}

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"darwin", "bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := groups.ResolveManager(mock)
	require.NoError(t, err)
	groupList, err := mm.List()
	require.NoError(t, err)

	grp := findGroup(groupList, "216")
	assert.Equal(t, "216", grp.ID)
	assert.Equal(t, int64(216), grp.Gid)
	assert.Equal(t, "_postgres", grp.Name)
	assert.Equal(t, []string{"_devicemgr", "_calendar", "_teamsserver", "_xserverdocs"}, grp.Members)

	assert.Equal(t, 3, len(groupList))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	mm, err := groups.ResolveManager(mock)
	require.NoError(t, err)
	groupList, err := mm.List()
	require.NoError(t, err)

	grp := findGroup(groupList, "0")
	assert.Equal(t, "0", grp.ID)
	assert.Equal(t, int64(0), grp.Gid)
	assert.Equal(t, "wheel", grp.Name)
	assert.Equal(t, []string{"root", "vagrant"}, grp.Members)

	assert.Equal(t, 36, len(groupList))
}

func TestManagerWindows(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"windows", "os"},
		},
	}, mock.WithPath("./testdata/windows.toml"))
	require.NoError(t, err)

	mm, err := groups.ResolveManager(mock)
	require.NoError(t, err)
	groupList, err := mm.List()
	require.NoError(t, err)

	grp := findGroup(groupList, "S-1-5-32-544")
	assert.Equal(t, "S-1-5-32-544", grp.ID)
	assert.Equal(t, int64(-1), grp.Gid)
	assert.Equal(t, "Administrators", grp.Name)
	// The last member is an orphaned SID (a deleted foreign account), which
	// Get-LocalGroupMember fails on. It is named by its SID.
	assert.Equal(t, []string{
		"WIN-HOST\\Administrator",
		"WIN-HOST\\mqladmin",
		"S-1-5-21-1111111111-2222222222-3333333333-1105",
	}, grp.Members)
	assert.Equal(t, []string{
		"S-1-5-21-1111111111-2222222222-3333333333-500",
		"S-1-5-21-1111111111-2222222222-3333333333-1000",
		"S-1-5-21-1111111111-2222222222-3333333333-1105",
	}, grp.MemberSids)
	assert.False(t, grp.MembersUnknown)

	grp = findGroup(groupList, "S-1-5-32-555")
	assert.Equal(t, "Remote Desktop Users", grp.Name)
	assert.Equal(t, []string{}, grp.Members)
	// read and empty, not unreadable
	assert.False(t, grp.MembersUnknown)

	assert.Equal(t, 25, len(groupList))
}

func findGroup(groupList []*groups.Group, id string) *groups.Group {
	if len(groupList) == 0 {
		return nil
	}

	for i := range groupList {
		if groupList[i].ID == id {
			return groupList[i]
		}
	}
	return nil
}
