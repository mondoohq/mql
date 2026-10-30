// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

func TestHandlerLoadsHiveFile(t *testing.T) {
	path := fixtureHive(t, t.TempDir())
	rh := NewRegistryHandler()
	require.NoError(t, rh.LoadSubkey(Software, path))

	items, err := rh.GetNativeRegistryKeyItems(Software, "Values")
	require.NoError(t, err)
	assert.Len(t, items, 15)
	assert.Equal(t, "hello world", itemByName(t, items, "Sz").Value.String)

	v, err := rh.GetRegistryItemValue(Software, "Values", "Dword")
	require.NoError(t, err)
	assert.Equal(t, int64(112), v.Value.Number)

	t.Run("children carry the requested path like on windows", func(t *testing.T) {
		children, err := rh.GetNativeRegistryKeyChildren(Software, "Many")
		require.NoError(t, err)
		require.Len(t, children, 1500)
		for _, c := range children {
			assert.Equal(t, `HKLM\TMPREG_SOFTWARE\Many`, c.Path)
		}
	})

	t.Run("callers append the child name to its path", func(t *testing.T) {
		children, err := rh.GetNativeRegistryKeyChildren(Software, "Many")
		require.NoError(t, err)
		child := children[len(children)-1]
		items, err := GetNativeRegistryKeyItems(child.Path + `\` + child.Name)
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Equal(t, "Index", items[0].Key)
		assert.Equal(t, DWORD, items[0].Value.Kind)
	})

	t.Run("package level readers", func(t *testing.T) {
		ok, err := NativeRegistryKeyExists(`hklm\tmpreg_software\nested\LEVEL2`)
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = NativeRegistryKeyExists(`HKEY_LOCAL_MACHINE\TMPREG_SOFTWARE\Nested\Nope`)
		require.NoError(t, err)
		assert.False(t, ok)
		item, err := GetNativeRegistryKeyItem(`HKLM\TMPREG_SOFTWARE\Values`, "sz")
		require.NoError(t, err)
		assert.Equal(t, "hello world", item.Value.String)
		_, err = GetNativeRegistryKeyItems(`HKLM\TMPREG_SOFTWARE\Nope`)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("paths outside a loaded hive are not supported", func(t *testing.T) {
		for _, p := range []string{
			`HKLM\SOFTWARE\Microsoft`,
			`HKLM\TMPREG_SYSTEM\Values`,
			`HKCU\TMPREG_SOFTWARE\Values`,
			`TMPREG_SOFTWARE\Values`,
			``,
		} {
			_, err := GetNativeRegistryKeyItems(p)
			assert.Error(t, err, p)
			_, err = GetNativeRegistryKeyChildren(p)
			assert.Error(t, err, p)
			_, err = NativeRegistryKeyExists(p)
			assert.Error(t, err, p)
			_, err = GetNativeRegistryKeyItem(p, "Sz")
			assert.Error(t, err, p)
		}
	})

	require.NoError(t, rh.UnloadSubkeys())
	_, err = rh.GetNativeRegistryKeyItems(Software, "Values")
	assert.Error(t, err, "handler no longer knows the hive")
	_, err = GetNativeRegistryKeyItems(`HKLM\TMPREG_SOFTWARE\Values`)
	assert.Error(t, err, "the hive is closed")
}

func TestHandlerLoadErrors(t *testing.T) {
	rh := NewRegistryHandler()
	assert.Error(t, rh.LoadSubkey("NOTAHIVE", fixtureHive(t, t.TempDir())), "unknown registry id")
	assert.Error(t, rh.LoadSubkey(Software, t.TempDir()+"/missing"))
	_, err := rh.GetNativeRegistryKeyItems(Software, "Values")
	assert.Error(t, err)
}

func TestHandlerLoadUserHive(t *testing.T) {
	path := fixtureHive(t, t.TempDir())
	rh := NewRegistryHandler()
	t.Cleanup(func() { assert.NoError(t, rh.UnloadSubkeys()) })
	sid := "S-1-5-21-1-2-3-1001"
	require.NoError(t, rh.LoadUserHive(sid, path))
	// loading again is a no-op
	require.NoError(t, rh.LoadUserHive(sid, path))

	items, err := rh.GetUserHiveKeyItems(sid, "Values")
	require.NoError(t, err)
	assert.Len(t, items, 15)
	ok, err := rh.UserHiveKeyExists(sid, `Nested\Level2`)
	require.NoError(t, err)
	assert.True(t, ok)
	children, err := rh.GetUserHiveKeyChildren(sid, "Nested")
	require.NoError(t, err)
	require.Len(t, children, 1)
	assert.Equal(t, "Level2", children[0].Name)
}

func TestHandlerUnloadSubkeysUnloadsEveryHiveWhenOneFails(t *testing.T) {
	path := fixtureHive(t, t.TempDir())
	rh := NewRegistryHandler()
	require.NoError(t, rh.LoadSubkey(Software, path))
	require.NoError(t, rh.LoadSubkey(System, path))

	// make both unloads fail: their files are already closed
	loadedHivesLock.Lock()
	for _, id := range []string{"tmpreg_software", "tmpreg_system"} {
		require.Contains(t, loadedHives, id)
		require.NoError(t, loadedHives[id].file.Close())
	}
	loadedHivesLock.Unlock()

	require.Error(t, rh.UnloadSubkeys())

	// Every hive was released, not only the first one that failed: both ids
	// can be mounted again. Returning on the first error left the other one
	// mounted, and loading it again failed with "already loaded".
	other := NewRegistryHandler()
	t.Cleanup(func() { assert.NoError(t, other.UnloadSubkeys()) })
	require.NoError(t, other.LoadSubkey(Software, path))
	require.NoError(t, other.LoadSubkey(System, path))

	// the hives that failed stay in the handler, and a retry clears them
	assert.NoError(t, rh.UnloadSubkeys())
	_, err := rh.GetNativeRegistryKeyItems(Software, "Values")
	assert.Error(t, err)
}
