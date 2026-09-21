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
// canned, so the profile-enumeration and live-hive-read logic can be
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

// fakeUserHiveHandler is a userHiveHandler whose contents are entirely
// canned, so getProfileInstalledApps' loaded-hive (!live) branch can be
// unit-tested without a real Windows registry. The real RegistryHandler only
// does anything on a Windows build (registry/registryhandler_unix.go), so on
// non-Windows CI that branch can never execute through the real
// implementation -- this fake is the seam that lets it run anyway.
type fakeUserHiveHandler struct {
	loadErr    error
	children   map[string][]registry.RegistryKeyChild // keyed "sid|subpath"
	items      map[string][]registry.RegistryKeyItem  // keyed "sid|subpath"
	loadedSid  string
	loadedPath string
	unloaded   bool
}

func (f *fakeUserHiveHandler) LoadUserHive(sid, filepath string) error {
	if f.loadErr != nil {
		return f.loadErr
	}
	f.loadedSid = sid
	f.loadedPath = filepath
	return nil
}

func (f *fakeUserHiveHandler) GetUserHiveKeyChildren(sid, path string) ([]registry.RegistryKeyChild, error) {
	return f.children[sid+"|"+path], nil
}

func (f *fakeUserHiveHandler) GetUserHiveKeyItems(sid, path string) ([]registry.RegistryKeyItem, error) {
	return f.items[sid+"|"+path], nil
}

func (f *fakeUserHiveHandler) UnloadSubkeys() error {
	f.unloaded = true
	return nil
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

// TestIsValidSID pins the shape check that keeps a ProfileList ".bak"
// leftover (a temp-profile repair artifact) from being treated as a real
// SID and handed to `reg load`.
func TestIsValidSID(t *testing.T) {
	tests := []struct {
		sid  string
		want bool
	}{
		{"S-1-5-21-1111111111-2222222222-3333333333-1001", true},
		{"S-1-5-18", true},
		{"S-1-5-21-1111111111-2222222222-3333333333-1001.bak", false},
		{"S-1-5-21-1111111111-2222222222-3333333333-1001.bak.bak", false},
		{"", false},
		{"not-a-sid", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isValidSID(tt.sid), "sid %q", tt.sid)
	}
}

// TestExpandWindowsEnvPercent pins the fix for ProfileImagePath being
// REG_EXPAND_SZ: an unexpanded "%SystemDrive%" token makes the eventual
// NTUSER.DAT path invalid, so `reg load` fails and the profile is silently
// skipped.
func TestExpandWindowsEnvPercent(t *testing.T) {
	t.Setenv("SystemDrive", "C:")
	assert.Equal(t, `C:\Users\alice`, expandWindowsEnvPercent(`%SystemDrive%\Users\alice`))
	// A plain SZ value with no token passes through unchanged.
	assert.Equal(t, `C:\Users\alice`, expandWindowsEnvPercent(`C:\Users\alice`))
}

// TestInstallScopeForRegistryPath is the scope-derivation table test: HKLM
// (and its Wow6432Node sibling) is machine-wide, HKCU and HKEY_USERS\<sid>
// (and their Wow6432Node siblings) are user-scope, attributed to the right
// SID -- except when that SID is a well-known service account, in which case
// the entry is machine-scope with no user (LocalSystem's own HKCU is not a
// per-user install).
func TestInstallScopeForRegistryPath(t *testing.T) {
	const callingSid = "S-1-5-21-1-2-3-1001"
	const otherSid = "S-1-5-21-1-2-3-1002"

	tests := []struct {
		name      string
		path      string
		callerSid string
		wantScope string
		wantUser  string
	}{
		{
			name:      "HKLM",
			path:      `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeMachine,
			wantUser:  "",
		},
		{
			name:      "HKLM Wow6432Node",
			path:      `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeMachine,
			wantUser:  "",
		},
		{
			name:      "HKCU",
			path:      `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeUser,
			wantUser:  callingSid,
		},
		{
			name:      "HKCU Wow6432Node",
			path:      `HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeUser,
			wantUser:  callingSid,
		},
		{
			name:      "HKEY_USERS sid",
			path:      `HKEY_USERS\` + otherSid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeUser,
			wantUser:  otherSid,
		},
		{
			name:      "HKEY_USERS sid Wow6432Node",
			path:      `HKEY_USERS\` + otherSid + `\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeUser,
			wantUser:  otherSid,
		},
		{
			// LocalSystem running the scan: HKCU is S-1-5-18's own hive, not a
			// real user's. Must read as machine scope with no user, not
			// user/S-1-5-18.
			name:      "HKCU when caller is LocalSystem",
			path:      `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: "S-1-5-18",
			wantScope: installScopeMachine,
			wantUser:  "",
		},
		{
			name:      "HKCU when caller is NetworkService",
			path:      `HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: "S-1-5-20",
			wantScope: installScopeMachine,
			wantUser:  "",
		},
		{
			// Defensive: a HKEY_USERS root keyed on a well-known service SID
			// (never produced by listWindowsProfiles, which filters those out
			// before building a windowsProfile) still reads as machine scope.
			name:      "HKEY_USERS sid is well-known system SID",
			path:      `HKEY_USERS\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
			callerSid: callingSid,
			wantScope: installScopeMachine,
			wantUser:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, user := installScopeForRegistryPath(tt.path, tt.callerSid)
			assert.Equal(t, tt.wantScope, scope)
			assert.Equal(t, tt.wantUser, user)
		})
	}
}

func TestListWindowsProfiles(t *testing.T) {
	t.Setenv("SystemDrive", "C:")
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
				// a temp-profile ".bak" leftover - not a valid SID, must be skipped
				{Path: profileListPath, Name: "S-1-5-21-1-2-3-1003.bak"},
				// REG_EXPAND_SZ ProfileImagePath - must be expanded
				{Path: profileListPath, Name: "S-1-5-21-1-2-3-1004"},
			},
		},
		items: map[string][]registry.RegistryKeyItem{
			profileListPath + `\S-1-5-21-1-2-3-1001`: {
				{Key: "ProfileImagePath", Value: sz(`C:\Users\alice`)},
			},
			profileListPath + `\S-1-5-21-1-2-3-1004`: {
				{Key: "ProfileImagePath", Value: sz(`%SystemDrive%\Users\dave`)},
			},
		},
	}

	profiles := listWindowsProfiles(reader)
	require.Len(t, profiles, 2)

	byName := map[string]windowsProfile{}
	for _, p := range profiles {
		byName[p.SID] = p
	}
	require.Contains(t, byName, "S-1-5-21-1-2-3-1001")
	assert.Equal(t, `C:\Users\alice`, byName["S-1-5-21-1-2-3-1001"].Path)

	require.Contains(t, byName, "S-1-5-21-1-2-3-1004")
	assert.Equal(t, `C:\Users\dave`, byName["S-1-5-21-1-2-3-1004"].Path, "REG_EXPAND_SZ ProfileImagePath must be expanded")

	assert.NotContains(t, byName, "S-1-5-21-1-2-3-1003.bak", "a .bak leftover is not a valid SID and must be skipped")
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
	// live=true, so the hive handler factory is never called - nil proves it.
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

func TestGetProfileInstalledAppsNotLiveEmptyProfilePath(t *testing.T) {
	w := &WinPkgManager{platform: testWinPlatform()}
	// A profile with no on-disk path recorded has nothing to load NTUSER.DAT
	// from. Not a failure, just nothing more that can be done for this
	// profile - and the hive handler factory must never even be called, nil
	// proves it.
	pkgs, err := w.getProfileInstalledApps(windowsProfile{SID: "S-1-5-21-1-2-3-1001", Path: ""}, &fakeRegistryReader{}, nil)
	require.NoError(t, err)
	assert.Nil(t, pkgs)
}

// TestGetProfileInstalledAppsHiveLoadFailureIsSkippedNotFatal proves a profile
// whose hive cannot be loaded (locked, missing NTUSER.DAT) surfaces as an
// error from getProfileInstalledApps that the caller
// (getPerProfileInstalledAppsWith) logs and skips, never as a failed scan.
// LoadRegistrySubkey has no real implementation on a non-Windows build (see
// registry/registryhandler_unix.go), so newDefaultUserHiveHandler's real
// RegistryHandler exercises the real failure path here without needing
// Windows.
func TestGetProfileInstalledAppsHiveLoadFailureIsSkippedNotFatal(t *testing.T) {
	w := &WinPkgManager{platform: testWinPlatform()}

	_, err := w.getProfileInstalledApps(windowsProfile{SID: "S-1-5-21-1-2-3-1001", Path: `C:\Users\alice`}, &fakeRegistryReader{}, newDefaultUserHiveHandler)
	require.Error(t, err)

	// getPerProfileInstalledAppsWith must not propagate that error: a profile
	// whose hive cannot be loaded is skipped, not fatal to the scan.
	reader := &fakeRegistryReader{
		children: map[string][]registry.RegistryKeyChild{
			profileListPath: {{Path: profileListPath, Name: "S-1-5-21-1-2-3-1001"}},
		},
		items: map[string][]registry.RegistryKeyItem{
			profileListPath + `\S-1-5-21-1-2-3-1001`: {{Key: "ProfileImagePath", Value: sz(`C:\Users\alice`)}},
		},
	}
	pkgs := w.getPerProfileInstalledAppsWith("", reader, newDefaultUserHiveHandler)
	assert.Empty(t, pkgs)
}

// TestGetProfileInstalledAppsLoadedHive walks getProfileInstalledApps' !live
// branch end to end through fakeUserHiveHandler: a profile with no live
// session loads NTUSER.DAT, reads the joined subpath
// (Software\...\Uninstall\<leaf>) through GetUserHiveKeyChildren/Items, and
// unloads the hive again right after — proving both finding (13)'s coverage
// gap and finding (2)'s unload-immediately fix in one place.
func TestGetProfileInstalledAppsLoadedHive(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	const subpath = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

	hive := &fakeUserHiveHandler{
		children: map[string][]registry.RegistryKeyChild{
			sid + "|" + subpath: {{Path: `HKLM\TMPREG_USER_` + sid + `\` + subpath, Name: "MyApp"}},
		},
		items: map[string][]registry.RegistryKeyItem{
			// getProfileInstalledApps reads items at sp + `\` + c.Name, i.e. the
			// joined subpath -- this is exactly what this test asserts.
			sid + "|" + subpath + `\MyApp`: {
				{Key: "DisplayName", Value: sz("Loaded Hive App")},
				{Key: "DisplayVersion", Value: sz("4.5.6")},
				{Key: "UninstallString", Value: sz("uninstall.exe")},
				{Key: "InstallLocation", Value: sz(`C:\Users\alice\AppData\Local\Programs\LoadedHiveApp`)},
			},
		},
	}

	w := &WinPkgManager{platform: testWinPlatform()}
	pkgs, err := w.getProfileInstalledApps(
		windowsProfile{SID: sid, Path: `C:\Users\alice`},
		&fakeRegistryReader{}, // IsUserHiveLoaded is always false => !live branch
		func() userHiveHandler { return hive },
	)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "Loaded Hive App", pkgs[0].Name)
	assert.Equal(t, "4.5.6", pkgs[0].Version)
	assert.Equal(t, installScopeUser, pkgs[0].InstallScope)
	assert.Equal(t, sid, pkgs[0].InstallUser)
	require.Len(t, pkgs[0].Files, 1)
	assert.Equal(t, `C:\Users\alice\AppData\Local\Programs\LoadedHiveApp`, pkgs[0].Files[0].Path)

	assert.Equal(t, sid, hive.loadedSid)
	assert.Equal(t, `C:\Users\alice\NTUSER.DAT`, hive.loadedPath, "must load the NTUSER.DAT under the profile path")
	assert.True(t, hive.unloaded, "the hive must be unloaded right after the two key reads, not held for the rest of the scan")
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
	pkgs := w.getPerProfileInstalledAppsWith(callingSid, reader, newDefaultUserHiveHandler)

	require.Len(t, pkgs, 1, "the calling identity's own profile must not be enumerated again")
	assert.Equal(t, "Bob App", pkgs[0].Name)
	assert.Equal(t, installScopeUser, pkgs[0].InstallScope)
	assert.Equal(t, otherSid, pkgs[0].InstallUser)
}
