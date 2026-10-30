// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestExpandWindowsProfilePath(t *testing.T) {
	env := map[string]any{"SystemDrive": "C:", "empty": "", "invalid": 42}
	for _, path := range []string{`%missing%\Users\alice`, `%empty%\Users\alice`, `%invalid%\Users\alice`} {
		_, err := expandWindowsProfilePath(path, env)
		require.Error(t, err)
	}
	path, err := expandWindowsProfilePath(`%systemdrive%\Users\alice`, env)
	require.NoError(t, err)
	assert.Equal(t, `C:\Users\alice`, path)
}

func TestExpandWindowsProfilePathFirstUnavailableVariable(t *testing.T) {
	env := map[string]any{"SystemDrive": "C:", "empty": "", "invalid": 42}
	for _, tc := range []struct {
		path     string
		variable string
	}{
		{`%missing1%\%missing2%\Users\alice`, "missing1"},
		{`%empty%\%missing%\Users\alice`, "empty"},
		{`%invalid%\%missing%\Users\alice`, "invalid"},
		{`%systemdrive%\%missing1%\%missing2%\alice`, "missing1"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			_, err := expandWindowsProfilePath(tc.path, env)
			require.ErrorContains(t, err, "environment variable "+tc.variable+" is unavailable")
		})
	}
}

func cacheProfileRegistryName(t *testing.T, runtime *plugin.Runtime, path, name, value string) {
	t.Helper()
	if strings.HasPrefix(path, `HKEY_USERS\`) {
		raw, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData("HKEY_USERS")})
		require.NoError(t, err)
		sid, _, _ := strings.Cut(strings.TrimPrefix(path, `HKEY_USERS\`), `\`)
		raw.(*mqlRegistrykey).Children = plugin.TValue[[]any]{State: plugin.StateIsSet, Data: []any{sid}}
	}
	raw, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData(path)})
	require.NoError(t, err)
	raw.(*mqlRegistrykey).Items = plugin.TValue[[]any]{State: plugin.StateIsSet, Data: []any{
		&mqlRegistrykeyProperty{Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet}, Value: plugin.TValue[string]{Data: value, State: plugin.StateIsSet}},
	}}
}

func TestTargetUserHomesWindowsProfiles(t *testing.T) {
	localSid, aadSid := "S-1-5-21-1-2-3-1001", "S-1-12-1-111-222-333-444"
	runtime, _ := vscodeProfileRuntime(t, map[string]string{
		localSid: `C:\Users\old.name`, aadSid: `C:\Users\entra.profile`,
		"S-1-5-21-4-5-6-1001": `C:\Users\domain.user`,
		"S-1-5-18":            `C:\Users\system`, "S-1-5-21-1-2-3-1002": `C:\Users\Public`,
	})
	cacheProfileRegistryName(t, runtime, `HKEY_USERS\`+localSid+`\Volatile Environment`, "username", "renamed.user")
	cacheProfileRegistryName(t, runtime, `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore\Cache\`+aadSid+`\IdentityCache\`+aadSid, "UserName", "entra@example.test")
	homes, err := targetUserHomes(runtime)
	require.NoError(t, err)
	assert.ElementsMatch(t, []targetUser{
		{sid: localSid, name: "renamed.user", home: `C:\Users\old.name`, uid: -1},
		{sid: aadSid, name: "entra@example.test", home: `C:\Users\entra.profile`, uid: -1},
		{sid: "S-1-5-21-4-5-6-1001", name: "domain.user", home: `C:\Users\domain.user`, uid: -1},
	}, homes)
}

func TestTargetHomeDirWindowsPrefersLoggedInRenamedUser(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1002"
	runtime, _ := vscodeProfileRuntime(t, map[string]string{
		"S-1-5-21-1-2-3-1001": `C:\Users\alice`, sid: `C:\Users\old.name`,
	})
	cacheProfileRegistryName(t, runtime, `HKEY_USERS\`+sid+`\Volatile Environment`, "USERNAME", "renamed.user")
	_, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("query user"), "exitcode": llx.IntData(0),
		"stdout": llx.StringData(" USERNAME SESSIONNAME ID STATE\n>renamed.user console 1 Active\n"),
	})
	require.NoError(t, err)
	home, err := targetHomeDir(runtime)
	require.NoError(t, err)
	assert.Equal(t, `C:\Users\old.name`, home)
}

func TestTargetUserHomesKeepsCachedAccountIdentity(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	runtime, _ := vscodeProfileRuntime(t, map[string]string{sid: `C:\Users\old.name`})
	seedUsersCache(t, runtime, &mqlUser{
		Name: plugin.TValue[string]{Data: "current.account", State: plugin.StateIsSet},
		Sid:  plugin.TValue[string]{Data: sid, State: plugin.StateIsSet},
		Uid:  plugin.TValue[int64]{Data: -1, State: plugin.StateIsSet},
		Home: plugin.TValue[string]{Data: `C:\Users\old.name`, State: plugin.StateIsSet},
	})
	raw, _ := runtime.Resources.Get("users\x00")
	cached := raw.(*mqlUsers)
	require.NoError(t, cached.refreshCache(cached.List.Data))
	homes, err := targetUserHomes(runtime)
	require.NoError(t, err)
	require.Len(t, homes, 1)
	assert.Equal(t, "current.account", homes[0].name)
	assert.Equal(t, int64(-1), homes[0].uid)
}

func TestTargetUserHomesDoesNotWaitForAccountEnumeration(t *testing.T) {
	runtime, _ := vscodeProfileRuntime(t, map[string]string{"S-1-5-21-1-2-3-1001": `C:\Users\alice`})
	raw, _ := runtime.Resources.Get("users\x00")
	users := raw.(*mqlUsers)
	users.lock.Lock()
	result := make(chan error, 1)
	go func() { _, err := targetUserHomes(runtime); result <- err }()
	select {
	case err := <-result:
		users.lock.Unlock()
		require.NoError(t, err)
	case <-time.After(time.Second):
		users.lock.Unlock()
		require.NoError(t, <-result)
		t.Fatal("profile inventory waited for the account enumeration lock")
	}
}

func TestTargetUserHomesUnixIdentity(t *testing.T) {
	runtime := memFSRuntime(t, afero.NewMemMapFs())
	seedUsersCache(t, runtime, &mqlUser{
		Name: plugin.TValue[string]{Data: "alice", State: plugin.StateIsSet},
		Uid:  plugin.TValue[int64]{Data: 501, State: plugin.StateIsSet},
		Home: plugin.TValue[string]{Data: "/home/alice", State: plugin.StateIsSet},
	})
	homes, err := targetUserHomes(runtime)
	require.NoError(t, err)
	assert.Equal(t, []targetUser{{name: "alice", home: "/home/alice", uid: 501}}, homes)
}

func TestWindowsProfileErrorsFailInventory(t *testing.T) {
	runtime, _ := vscodeProfileRuntime(t, nil)
	raw, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData(windowsProfileListPath)})
	require.NoError(t, err)
	raw.(*mqlRegistrykey).Children.Error = llx.Forbidden(errors.New("profile read denied"))
	for _, name := range []string{"chrome", "firefox", "jetbrains", "ai"} {
		t.Run(name, func(t *testing.T) {
			resource, err := CreateResource(runtime, name, nil)
			require.NoError(t, err)
			var got error
			switch r := resource.(type) {
			case *mqlChrome:
				got = r.GetExtensions().Error
			case *mqlFirefox:
				got = r.GetAddons().Error
			case *mqlJetbrains:
				got = r.GetPlugins().Error
			case *mqlAi:
				got = r.GetModels().Error
			}
			require.ErrorIs(t, got, llx.ErrForbidden)
		})
	}
}

func TestWindowsCachedProfileIdentityConcurrentRefresh(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	runtime, _ := vscodeProfileRuntime(t, map[string]string{sid: `C:\Users\old.name`})
	seedUsersCache(t, runtime, &mqlUser{
		Name: plugin.TValue[string]{Data: "current.account", State: plugin.StateIsSet},
		Sid:  plugin.TValue[string]{Data: sid, State: plugin.StateIsSet},
		Uid:  plugin.TValue[int64]{Data: -1, State: plugin.StateIsSet},
		Home: plugin.TValue[string]{Data: `C:\Users\old.name`, State: plugin.StateIsSet},
	})
	raw, _ := runtime.Resources.Get("users\x00")
	users := raw.(*mqlUsers)
	require.NoError(t, users.refreshCache(nil))
	hive, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData("HKEY_USERS")})
	require.NoError(t, err)
	hive.(*mqlRegistrykey).Children = plugin.TValue[[]any]{State: plugin.StateIsSet}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			if err := users.refreshCache(nil); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 1000 {
		profiles := []targetUser{{sid: sid, name: "old.name", home: `C:\Users\old.name`, uid: -1}}
		enrichWindowsProfileNames(runtime, profiles)
		assert.Contains(t, []string{"current.account", "old.name"}, profiles[0].name)
	}
	wg.Wait()
	homes, err := targetUserHomes(runtime)
	require.NoError(t, err)
	require.Len(t, homes, 1)
	assert.Equal(t, "current.account", homes[0].name)
}
