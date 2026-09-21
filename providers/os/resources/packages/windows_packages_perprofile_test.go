// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/registry"
)

// fakeRegistryReader is a nativeRegistryReader whose contents are entirely
// canned, so the profile-enumeration and per-profile-hive-read logic can be
// unit-tested without a real Windows registry.
type fakeRegistryReader struct {
	children    map[string][]registry.RegistryKeyChild
	childrenErr map[string]error
	items       map[string][]registry.RegistryKeyItem
	liveHives   map[string]bool
}

func (f *fakeRegistryReader) Children(path string) ([]registry.RegistryKeyChild, error) {
	if f.childrenErr != nil {
		if err, ok := f.childrenErr[path]; ok {
			return nil, err
		}
	}
	return f.children[path], nil
}

func (f *fakeRegistryReader) Items(path string) ([]registry.RegistryKeyItem, error) {
	return f.items[path], nil
}

func (f *fakeRegistryReader) IsUserHiveLoaded(sid string) bool {
	return f.liveHives[sid]
}

// fakeUserHiveLoader satisfies userHiveLoader with a caller-supplied handler,
// so getProfileInstalledApps' NTUSER.DAT-loading branch can be exercised
// without a real connection.
type fakeUserHiveLoader struct {
	rh *registry.RegistryHandler
}

func (f *fakeUserHiveLoader) UserHiveRegistryHandler() *registry.RegistryHandler {
	return f.rh
}

func sz(s string) registry.RegistryKeyValue {
	return registry.RegistryKeyValue{Kind: registry.SZ, String: s}
}

func TestIsWellKnownSystemSID(t *testing.T) {
	tests := []struct {
		sid  string
		want bool
	}{
		{"S-1-5-18", true},
		{"S-1-5-19", true},
		{"S-1-5-20", true},
		{"s-1-5-18", true}, // case-insensitive
		{".DEFAULT", true},
		{".default", true},
		{"S-1-5-21-1111111111-2222222222-3333333333-1001", false},
		{"", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isWellKnownSystemSID(tt.sid), "sid %q", tt.sid)
	}
}

// TestInstallScopeForRegistryPath is the scope-derivation table test: HKLM
// (and its Wow6432Node sibling) is machine-wide, HKCU and HKEY_USERS\<sid>
// (and their Wow6432Node siblings) are user-scope, attributed to the right SID.
func TestInstallScopeForRegistryPath(t *testing.T) {
	const callingSid = "S-1-5-21-1-2-3-1001"
	const otherSid = "S-1-5-21-1-2-3-1002"

	tests := []struct {
		name      string
		path      string
		wantScope string
		wantUser  string
	}{
		{
			name:      "HKLM",
			path:      `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			wantScope: installScopeMachine,
			wantUser:  "",
		},
		{
			name:      "HKLM Wow6432Node",
			path:      `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			wantScope: installScopeMachine,
			wantUser:  "",
		},
		{
			name:      "HKCU",
			path:      `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			wantScope: installScopeUser,
			wantUser:  callingSid,
		},
		{
			name:      "HKCU Wow6432Node",
			path:      `HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			wantScope: installScopeUser,
			wantUser:  callingSid,
		},
		{
			name:      "HKEY_USERS sid",
			path:      `HKEY_USERS\` + otherSid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
			wantScope: installScopeUser,
			wantUser:  otherSid,
		},
		{
			name:      "HKEY_USERS sid Wow6432Node",
			path:      `HKEY_USERS\` + otherSid + `\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			wantScope: installScopeUser,
			wantUser:  otherSid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, user := installScopeForRegistryPath(tt.path, callingSid)
			assert.Equal(t, tt.wantScope, scope)
			assert.Equal(t, tt.wantUser, user)
		})
	}
}

func TestListWindowsProfiles(t *testing.T) {
	reader := &fakeRegistryReader{
		children: map[string][]registry.RegistryKeyChild{
			profileListPath: {
				{Path: profileListPath, Name: "S-1-5-18"},
				{Path: profileListPath, Name: "S-1-5-19"},
				{Path: profileListPath, Name: "S-1-5-20"},
				{Path: profileListPath, Name: ".DEFAULT"},
				{Path: profileListPath, Name: "S-1-5-21-1-2-3-1001"},
				// no ProfileImagePath recorded for this one - should be skipped
				{Path: profileListPath, Name: "S-1-5-21-1-2-3-1002"},
			},
		},
		items: map[string][]registry.RegistryKeyItem{
			profileListPath + `\S-1-5-21-1-2-3-1001`: {
				{Key: "ProfileImagePath", Value: sz(`C:\Users\alice`)},
			},
		},
	}

	profiles := listWindowsProfiles(reader)
	require.Len(t, profiles, 1)
	assert.Equal(t, "S-1-5-21-1-2-3-1001", profiles[0].SID)
	assert.Equal(t, `C:\Users\alice`, profiles[0].Path)
}

func TestListWindowsProfilesEnumerationFailure(t *testing.T) {
	reader := &fakeRegistryReader{
		childrenErr: map[string]error{
			profileListPath: errors.New("access denied"),
		},
	}
	profiles := listWindowsProfiles(reader)
	assert.Nil(t, profiles)
}

func testWinPlatform() *inventory.Platform {
	return &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}}
}

func TestGetProfileInstalledAppsLiveHive(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	basePath := `HKEY_USERS\` + sid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`

	reader := &fakeRegistryReader{
		liveHives: map[string]bool{sid: true},
		children: map[string][]registry.RegistryKeyChild{
			basePath: {{Path: basePath, Name: "MyApp"}},
		},
		items: map[string][]registry.RegistryKeyItem{
			basePath + `\MyApp`: {
				{Key: "DisplayName", Value: sz("My App")},
				{Key: "DisplayVersion", Value: sz("1.2.3")},
				{Key: "UninstallString", Value: sz("uninstall.exe")},
				{Key: "InstallLocation", Value: sz(`C:\Users\alice\AppData\Local\Programs\MyApp`)},
			},
		},
	}

	w := &WinPkgManager{platform: testWinPlatform()}
	pkgs, err := w.getProfileInstalledApps(windowsProfile{SID: sid, Path: `C:\Users\alice`}, reader, nil)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "My App", pkgs[0].Name)
	assert.Equal(t, "1.2.3", pkgs[0].Version)
	assert.Equal(t, installScopeUser, pkgs[0].InstallScope)
	assert.Equal(t, sid, pkgs[0].InstallUser)
	require.Len(t, pkgs[0].Files, 1)
	assert.Equal(t, `C:\Users\alice\AppData\Local\Programs\MyApp`, pkgs[0].Files[0].Path)
}

func TestGetProfileInstalledAppsNotLiveNoLoader(t *testing.T) {
	w := &WinPkgManager{platform: testWinPlatform()}
	// Not live (fakeRegistryReader.liveHives is nil, so IsUserHiveLoaded is
	// always false) and no loader - this is the remote/non-local-Windows
	// case, or a profile this connection cannot load NTUSER.DAT for. Not a
	// failure, just nothing more that can be done for this profile.
	pkgs, err := w.getProfileInstalledApps(windowsProfile{SID: "S-1-5-21-1-2-3-1001", Path: `C:\Users\alice`}, &fakeRegistryReader{}, nil)
	require.NoError(t, err)
	assert.Nil(t, pkgs)
}

func TestGetProfileInstalledAppsNotLiveEmptyProfilePath(t *testing.T) {
	w := &WinPkgManager{platform: testWinPlatform()}
	loader := &fakeUserHiveLoader{rh: registry.NewRegistryHandler()}
	// A profile with no on-disk path recorded has nothing to load NTUSER.DAT
	// from, even with a loader available.
	pkgs, err := w.getProfileInstalledApps(windowsProfile{SID: "S-1-5-21-1-2-3-1001", Path: ""}, &fakeRegistryReader{}, loader)
	require.NoError(t, err)
	assert.Nil(t, pkgs)
}

// hiveLoaderTestConnection is a shared.Connection (via the embedded
// snapTestConnection) that also satisfies userHiveLoader, the way
// connection/local.LocalConnection does on a real Windows host. Used to
// exercise the w.conn.(userHiveLoader) detection getPerProfileInstalledApps
// relies on in production.
type hiveLoaderTestConnection struct {
	*snapTestConnection
	rh *registry.RegistryHandler
}

func (c *hiveLoaderTestConnection) UserHiveRegistryHandler() *registry.RegistryHandler {
	return c.rh
}

// TestGetProfileInstalledAppsHiveLoadFailureIsSkippedNotFatal proves a profile
// whose hive cannot be loaded (locked, missing NTUSER.DAT) surfaces as an
// error from getProfileInstalledApps that the caller
// (getPerProfileInstalledAppsWith) logs and skips, never as a failed scan.
// LoadRegistrySubkey has no real implementation on a non-Windows build (see
// registry/registryhandler_unix.go), so this exercises the real failure path
// without needing Windows.
func TestGetProfileInstalledAppsHiveLoadFailureIsSkippedNotFatal(t *testing.T) {
	w := &WinPkgManager{platform: testWinPlatform()}
	loader := &fakeUserHiveLoader{rh: registry.NewRegistryHandler()}

	_, err := w.getProfileInstalledApps(windowsProfile{SID: "S-1-5-21-1-2-3-1001", Path: `C:\Users\alice`}, &fakeRegistryReader{}, loader)
	require.Error(t, err)

	// getPerProfileInstalledAppsWith must not propagate that error: a profile
	// whose hive cannot be loaded is skipped, not fatal to the scan. Route
	// through a connection that satisfies userHiveLoader, the same detection
	// production code performs via w.conn.(userHiveLoader).
	reader := &fakeRegistryReader{
		children: map[string][]registry.RegistryKeyChild{
			profileListPath: {{Path: profileListPath, Name: "S-1-5-21-1-2-3-1001"}},
		},
		items: map[string][]registry.RegistryKeyItem{
			profileListPath + `\S-1-5-21-1-2-3-1001`: {{Key: "ProfileImagePath", Value: sz(`C:\Users\alice`)}},
		},
	}
	w.conn = &hiveLoaderTestConnection{snapTestConnection: &snapTestConnection{}, rh: registry.NewRegistryHandler()}
	pkgs := w.getPerProfileInstalledAppsWith("", reader)
	assert.Empty(t, pkgs)
}

// TestGetPerProfileInstalledAppsSkipsCallingSid proves the calling identity's
// own profile is excluded from per-profile enumeration (its entries were
// already read via HKCU), while another user's profile is still reported.
func TestGetPerProfileInstalledAppsSkipsCallingSid(t *testing.T) {
	const callingSid = "S-1-5-21-1-2-3-1001"
	const otherSid = "S-1-5-21-1-2-3-1002"

	otherBasePath := `HKEY_USERS\` + otherSid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`
	callingBasePath := `HKEY_USERS\` + callingSid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`

	reader := &fakeRegistryReader{
		liveHives: map[string]bool{callingSid: true, otherSid: true},
		children: map[string][]registry.RegistryKeyChild{
			profileListPath: {
				{Path: profileListPath, Name: callingSid},
				{Path: profileListPath, Name: otherSid},
			},
			otherBasePath:   {{Path: otherBasePath, Name: "BobApp"}},
			callingBasePath: {{Path: callingBasePath, Name: "AliceApp"}},
		},
		items: map[string][]registry.RegistryKeyItem{
			profileListPath + `\` + callingSid: {{Key: "ProfileImagePath", Value: sz(`C:\Users\alice`)}},
			profileListPath + `\` + otherSid:   {{Key: "ProfileImagePath", Value: sz(`C:\Users\bob`)}},
			otherBasePath + `\BobApp`: {
				{Key: "DisplayName", Value: sz("Bob App")},
				{Key: "DisplayVersion", Value: sz("1.0")},
				{Key: "UninstallString", Value: sz("uninstall.exe")},
			},
			callingBasePath + `\AliceApp`: {
				{Key: "DisplayName", Value: sz("Alice App")},
				{Key: "DisplayVersion", Value: sz("2.0")},
				{Key: "UninstallString", Value: sz("uninstall.exe")},
			},
		},
	}

	w := &WinPkgManager{platform: testWinPlatform()}
	pkgs := w.getPerProfileInstalledAppsWith(callingSid, reader)

	require.Len(t, pkgs, 1, "the calling identity's own profile must not be enumerated again")
	assert.Equal(t, "Bob App", pkgs[0].Name)
	assert.Equal(t, installScopeUser, pkgs[0].InstallScope)
	assert.Equal(t, otherSid, pkgs[0].InstallUser)
}
