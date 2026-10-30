// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/users"
)

func TestManagerDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "linux", "debian"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := users.ResolveManager(mock)
	require.NoError(t, err)
	userList, err := mm.List()
	require.NoError(t, err)

	usr := findUser(userList, "0")
	assert.Equal(t, "0", usr.ID)
	assert.Equal(t, int64(0), usr.Uid)
	assert.Equal(t, int64(0), usr.Gid)
	assert.Equal(t, "/root", usr.Home)
	assert.Equal(t, "root", usr.Name)
	assert.Equal(t, "/bin/bash", usr.Shell)

	assert.Equal(t, 13, len(userList))
}

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := users.ResolveManager(mock)
	require.NoError(t, err)
	userList, err := mm.List()
	require.NoError(t, err)

	usr := findUser(userList, "0")
	assert.Equal(t, "0", usr.ID)
	assert.Equal(t, int64(0), usr.Uid)
	assert.Equal(t, int64(0), usr.Gid)
	assert.Equal(t, "/var/root /private/var/root", usr.Home)
	assert.Equal(t, "root", usr.Name)
	assert.Equal(t, "/bin/sh", usr.Shell)
	assert.False(t, usr.Enabled, "root has no AuthenticationAuthority")

	byName := map[string]*users.User{}
	for _, u := range userList {
		byName[u.Name] = u
	}
	assert.True(t, byName["daemon"].Enabled)
	assert.False(t, byName["_www"].Enabled, "DisabledUser alone")
	assert.False(t, byName["nobody"].Enabled, "DisabledUser before ShadowHash")

	assert.Equal(t, 8, len(userList))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "bsd"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	mm, err := users.ResolveManager(mock)
	require.NoError(t, err)
	userList, err := mm.List()
	require.NoError(t, err)

	usr := findUser(userList, "0")
	assert.Equal(t, "0", usr.ID)
	assert.Equal(t, int64(0), usr.Uid)
	assert.Equal(t, int64(0), usr.Gid)
	assert.Equal(t, "/root", usr.Home)
	assert.Equal(t, "root", usr.Name)
	assert.Equal(t, "/bin/csh", usr.Shell)

	assert.Equal(t, 28, len(userList))
}

func TestManagerWindows(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"windows"},
		},
	}, mock.WithPath("./testdata/windows.toml"))
	require.NoError(t, err)

	mm, err := users.ResolveManager(mock)
	require.NoError(t, err)
	userList, err := mm.List()
	require.NoError(t, err)

	usr := findUser(userList, "S-1-5-21-2356735557-1575748656-448136971-500")
	assert.Equal(t, "S-1-5-21-2356735557-1575748656-448136971-500", usr.ID)
	assert.Equal(t, int64(-1), usr.Uid)
	assert.Equal(t, int64(-1), usr.Gid)
	assert.Equal(t, `C:\Users\chris`, usr.Home)
	assert.Equal(t, "chris", usr.Name)
	assert.Equal(t, "", usr.Shell)

	// Accounts without a profile registry entry must surface as empty home,
	// not as a fabricated C:\Users\<Name>. Downstream filters (vscode, firefox)
	// rely on the empty value to skip them.
	guest := findUser(userList, "S-1-5-21-2356735557-1575748656-448136971-501")
	assert.Equal(t, "", guest.Home)

	// Domain user discovered via ProfileList (not via Get-LocalUser) must surface
	// with name + home so downstream resources (vscode.extensions, firefox.profiles,
	// ai_coding_tools) can iterate them on RDS / Citrix / domain-joined hosts.
	// Name comes from the ProfileImagePath leaf, never from LSA/AD.
	jane := findUser(userList, "S-1-5-21-9999999999-8888888888-7777777777-1001")
	assert.NotNil(t, jane, "domain user from ProfileList should appear in users.list")
	assert.Equal(t, "jane.doe", jane.Name)
	assert.Equal(t, `C:\Users\jane.doe`, jane.Home)
	assert.True(t, jane.Enabled)

	assert.Equal(t, 8, len(userList))
}

func findUser(userList []*users.User, id string) *users.User {
	if len(userList) == 0 {
		return nil
	}

	for i := range userList {
		if userList[i].ID == id {
			return userList[i]
		}
	}
	return nil
}
