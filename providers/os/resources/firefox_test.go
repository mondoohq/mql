// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirefoxFieldExtraction(t *testing.T) {
	extensionsJSON := `{
		"addons": [
			{
				"id": "uBlock0@raymondhill.net",
				"version": "1.56.0",
				"type": "extension",
				"description": "An efficient blocker.",
				"active": true,
				"userDisabled": false,
				"appDisabled": false,
				"visible": true,
				"path": "/home/user/.mozilla/firefox/abc.default/extensions/uBlock0@raymondhill.net.xpi",
				"sourceURI": "https://addons.mozilla.org/firefox/downloads/file/4290466/ublock_origin-1.56.0.xpi",
				"installDate": 1700000000000,
				"updateDate": 1710000000000,
				"location": "app-profile",
				"loader": null,
				"applyBackgroundUpdates": 1,
				"defaultLocale": {
					"name": "uBlock Origin",
					"description": "An efficient blocker.",
					"creator": "Raymond Hill"
				},
				"userPermissions": {
					"permissions": ["dns", "menus", "privacy", "storage", "tabs", "webNavigation", "webRequest", "webRequestBlocking"],
					"origins": ["<all_urls>"],
					"data_collection": []
				},
				"optionalPermissions": {
					"permissions": ["clipboardWrite"],
					"origins": []
				},
				"requestedPermissions": {
					"permissions": [],
					"origins": []
				}
			},
			{
				"id": "disabled@example.com",
				"name": "Disabled Addon",
				"version": "1.0.0",
				"type": "extension",
				"active": false,
				"userDisabled": true,
				"appDisabled": false,
				"visible": true,
				"path": "/home/user/.mozilla/firefox/abc.default/extensions/disabled@example.com.xpi",
				"installDate": 1700000000000,
				"updateDate": 1700000000000,
				"location": "app-profile",
				"applyBackgroundUpdates": 0,
				"defaultLocale": {
					"name": "Disabled Addon",
					"description": "A disabled addon."
				}
			},
			{
				"id": "appdisabled@example.com",
				"name": "App Disabled",
				"version": "1.0.0",
				"type": "extension",
				"active": false,
				"userDisabled": false,
				"appDisabled": true,
				"visible": true,
				"path": "/path/to/addon",
				"installDate": 1700000000000,
				"updateDate": 1700000000000,
				"location": "app-profile",
				"applyBackgroundUpdates": 2,
				"loader": "some-loader"
			}
		]
	}`

	var data firefoxExtensionsJSON
	err := json.Unmarshal([]byte(extensionsJSON), &data)
	require.NoError(t, err)
	require.Len(t, data.Addons, 3)

	// Test uBlock Origin
	ublock := data.Addons[0]
	assert.Equal(t, "uBlock0@raymondhill.net", ublock.ID)
	assert.True(t, ublock.Active)
	assert.False(t, ublock.UserDisabled)
	assert.False(t, ublock.AppDisabled)
	assert.Equal(t, "app-profile", ublock.Location)
	assert.Nil(t, ublock.Loader)
	assert.Equal(t, 1, int(ublock.ApplyBackgroundUpdates))

	// Name and creator: real entries carry these in defaultLocale only, so the
	// top-level fields stay empty and the locale has to supply them.
	assert.Empty(t, ublock.Name)
	require.NotNil(t, ublock.DefaultLocale)
	assert.Equal(t, "uBlock Origin", ublock.DefaultLocale.Name)
	assert.Equal(t, "Raymond Hill", ublock.DefaultLocale.Creator)

	// Derived: disabled
	assert.False(t, ublock.UserDisabled || ublock.AppDisabled)

	// Derived: autoupdate (applyBackgroundUpdates != 0 means on)
	assert.True(t, ublock.ApplyBackgroundUpdates != 0)

	// Derived: native (loader == nil && type == extension)
	assert.True(t, ublock.Loader == nil && ublock.Type == "extension")

	// Granted permissions come from userPermissions, and never from the
	// optionalPermissions/requestedPermissions siblings.
	require.NotNil(t, ublock.UserPermissions)
	merged := firefoxMergeStringSlices(ublock.UserPermissions.Permissions, ublock.UserPermissions.Origins)
	assert.Contains(t, merged, "dns")
	assert.Contains(t, merged, "<all_urls>")
	assert.Len(t, merged, 9)                        // 8 permissions + 1 origin
	assert.NotContains(t, merged, "clipboardWrite") // optional, not granted

	// Test disabled addon (user disabled)
	disabled := data.Addons[1]
	assert.True(t, disabled.UserDisabled)
	assert.False(t, disabled.AppDisabled)
	assert.True(t, disabled.UserDisabled || disabled.AppDisabled) // disabled = true
	assert.Equal(t, 0, int(disabled.ApplyBackgroundUpdates))
	assert.False(t, disabled.ApplyBackgroundUpdates != 0) // autoupdate = false
	assert.Nil(t, disabled.UserPermissions)               // no userPermissions field

	// Test app-disabled addon
	appDisabled := data.Addons[2]
	assert.False(t, appDisabled.UserDisabled)
	assert.True(t, appDisabled.AppDisabled)
	assert.True(t, appDisabled.UserDisabled || appDisabled.AppDisabled) // disabled = true
	assert.Equal(t, 2, int(appDisabled.ApplyBackgroundUpdates))
	assert.True(t, appDisabled.ApplyBackgroundUpdates != 0)                       // autoupdate = true
	assert.NotNil(t, appDisabled.Loader)                                          // non-nil loader
	assert.False(t, appDisabled.Loader == nil && appDisabled.Type == "extension") // native = false
}

func TestFirefoxSystemAddonDetection(t *testing.T) {
	tests := []struct {
		name     string
		addon    firefoxAddonEntry
		isSystem bool
	}{
		{
			name:     "locale addon",
			addon:    firefoxAddonEntry{Type: "locale", ID: "en-US@dictionaries.addons.mozilla.org"},
			isSystem: true,
		},
		{
			name:     "dictionary addon",
			addon:    firefoxAddonEntry{Type: "dictionary", ID: "en-US@dictionaries.addons.mozilla.org"},
			isSystem: true,
		},
		{
			name:     "mozilla.org system addon",
			addon:    firefoxAddonEntry{Type: "extension", ID: "formautofill@mozilla.org"},
			isSystem: true,
		},
		{
			name:     "user extension",
			addon:    firefoxAddonEntry{Type: "extension", ID: "uBlock0@raymondhill.net"},
			isSystem: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isSystem, isFirefoxSystemAddon(tt.addon))
		})
	}
}

func TestFirefoxBrowserDirExists(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/home/user/.mozilla/firefox/Profiles/abc.default", 0o755))
	require.NoError(t, afero.WriteFile(fs, "/home/user/.librewolf", []byte("not a dir"), 0o644))
	afs := &afero.Afero{Fs: fs}

	tests := []struct {
		name   string
		dir    string
		exists bool
	}{
		{
			name:   "installed browser",
			dir:    "/home/user/.mozilla/firefox",
			exists: true,
		},
		{
			name:   "browser not installed",
			dir:    "/home/user/.mozilla/firefox-nightly",
			exists: false,
		},
		{
			name:   "path exists but is a file",
			dir:    "/home/user/.librewolf",
			exists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, denied := firefoxBrowserDir(afs, tt.dir)
			assert.Equal(t, tt.exists, exists)
			assert.False(t, denied)
		})
	}
}

// firefoxDeniedFs refuses every path under one prefix, the way a non-root scan sees
// another user's 0750 home on Ubuntu 21.04 and later.
type firefoxDeniedFs struct {
	afero.Fs
	prefix string
	// unlistable is a directory that can be found but not listed, like
	// ~/.config/mozilla/firefox (0700) under a traversable ~/.config.
	unlistable string
}

func (d firefoxDeniedFs) Stat(name string) (os.FileInfo, error) {
	if strings.HasPrefix(name, d.prefix) {
		return nil, &os.PathError{Op: "stat", Path: name, Err: syscall.EACCES}
	}
	return d.Fs.Stat(name)
}

func (d firefoxDeniedFs) Open(name string) (afero.File, error) {
	if strings.HasPrefix(name, d.prefix) || (d.unlistable != "" && strings.HasPrefix(name, d.unlistable)) {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	return d.Fs.Open(name)
}

// A profile directory the scan may not enter is not an absent browser: it is
// a profile whose addons cannot be listed, and unreadableAddons must say so
// rather than let addons.none(...) pass on a list that skipped it.
func TestFirefoxBrowserDirDenied(t *testing.T) {
	base := afero.NewMemMapFs()
	require.NoError(t, base.MkdirAll("/home/alice/.mozilla/firefox", 0o755))
	afs := &afero.Afero{Fs: firefoxDeniedFs{Fs: base, prefix: "/home/alice/"}}

	exists, denied := firefoxBrowserDir(afs, "/home/alice/.mozilla/firefox")
	assert.False(t, exists)
	assert.True(t, denied)

	exists, denied = firefoxBrowserDir(afs, "/home/bob/.mozilla/firefox")
	assert.False(t, exists)
	assert.False(t, denied, "a missing directory is absence, not a refusal")
}

// Firefox creates its profile root 0700, so on Debian 12's XDG layout another
// user's ~/.config/mozilla/firefox is found but cannot be listed, and the
// profile search beneath it comes back empty without an error.
func TestFirefoxBrowserDirUnlistable(t *testing.T) {
	base := afero.NewMemMapFs()
	require.NoError(t, base.MkdirAll("/home/alice/.config/mozilla/firefox/abc.default-esr", 0o755))
	require.NoError(t, base.MkdirAll("/home/admin/.config/mozilla/firefox/def.default-esr", 0o755))
	afs := &afero.Afero{Fs: firefoxDeniedFs{Fs: base, prefix: "/nowhere/", unlistable: "/home/alice/.config/mozilla/firefox"}}

	exists, denied := firefoxBrowserDir(afs, "/home/alice/.config/mozilla/firefox")
	assert.False(t, exists)
	assert.True(t, denied)

	exists, denied = firefoxBrowserDir(afs, "/home/admin/.config/mozilla/firefox")
	assert.True(t, exists)
	assert.False(t, denied)
}

// The shape here was captured from a live macOS Firefox profile whose
// extensions.json holds 27 addons. One of them wrote applyBackgroundUpdates as
// the string "2" where every other entry used the number 2, and that single
// field made the whole file undecodable, costing the profile all 27. See #10906.
const firefoxMixedApplyBackgroundUpdates = `{
	"addons": [
		{
			"id": "uBlock0@raymondhill.net",
			"version": "1.60.0",
			"type": "extension",
			"active": true,
			"location": "app-profile",
			"applyBackgroundUpdates": 2,
			"userPermissions": { "permissions": ["dns", "storage"], "origins": ["<all_urls>"] }
		},
		{
			"id": "jid1-example@jetpack",
			"version": "5.24.4",
			"type": "extension",
			"active": true,
			"location": "app-profile",
			"applyBackgroundUpdates": "2",
			"userPermissions": { "permissions": ["cookies", "history"], "origins": ["https://*.example.com/*"] }
		},
		{
			"id": "sponsorBlocker@ajay.app",
			"version": "5.5.7",
			"type": "extension",
			"active": true,
			"location": "app-profile",
			"applyBackgroundUpdates": 0
		}
	]
}`

func TestFirefoxApplyBackgroundUpdatesAsString(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.WriteFile("/extensions.json", []byte(firefoxMixedApplyBackgroundUpdates), 0o644))

	data, err := readFirefoxExtensionsJSON(afs, "/extensions.json")
	require.NoError(t, err)

	// The whole point: one string-typed field must not cost the other addons.
	require.Len(t, data.Addons, 3)
	assert.Equal(t, 0, data.Unreadable)

	byID := map[string]firefoxAddonEntry{}
	for _, a := range data.Addons {
		byID[a.ID] = a
	}

	// "2" means "use the global default", exactly as the number 2 does, so
	// autoupdate is on for it, not off the way a zero value would report.
	assert.Equal(t, 2, int(byID["jid1-example@jetpack"].ApplyBackgroundUpdates))
	assert.Equal(t, 2, int(byID["uBlock0@raymondhill.net"].ApplyBackgroundUpdates))
	assert.Equal(t, 0, int(byID["sponsorBlocker@ajay.app"].ApplyBackgroundUpdates))

	// The permissions of the string-valued addon have to survive too. Before
	// the fix this addon and every sibling read as absent.
	perms := byID["jid1-example@jetpack"].UserPermissions
	require.NotNil(t, perms)
	assert.Equal(t, []string{"cookies", "history"}, perms.Permissions)
}

func TestFirefoxOneUnreadableAddonDoesNotBlindTheProfile(t *testing.T) {
	// The second entry is not an object at all, so no amount of type coercion
	// recovers it. It has to be skipped and counted, leaving the other two
	// readable: a shorter list carrying no signal is what a policy cannot see.
	extensionsJSON := `{
		"addons": [
			{ "id": "good1@example.com", "type": "extension", "location": "app-profile" },
			"this is not an addon object",
			{ "id": "good2@example.com", "type": "extension", "location": "app-profile" }
		]
	}`

	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.WriteFile("/extensions.json", []byte(extensionsJSON), 0o644))

	data, err := readFirefoxExtensionsJSON(afs, "/extensions.json")
	require.NoError(t, err)

	require.Len(t, data.Addons, 2)
	assert.Equal(t, 1, data.Unreadable)
	assert.Equal(t, "good1@example.com", data.Addons[0].ID)
	assert.Equal(t, "good2@example.com", data.Addons[1].ID)
}

func TestFirefoxMalformedFileStillErrors(t *testing.T) {
	// Per-addon recovery must not turn a file that is not JSON at all into an
	// empty success, which would report "no addons" for an unreadable profile.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.WriteFile("/extensions.json", []byte("{not json"), 0o644))

	_, err := readFirefoxExtensionsJSON(afs, "/extensions.json")
	assert.Error(t, err)
}

func TestFirefoxFlexIntUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected int
		wantErr  bool
	}{
		{name: "number", raw: `1`, expected: 1},
		{name: "quoted digit", raw: `"1"`, expected: 1},
		{name: "quoted zero", raw: `"0"`, expected: 0},
		{name: "negative", raw: `-1`, expected: -1},
		{name: "quoted negative", raw: `"-1"`, expected: -1},
		{name: "null", raw: `null`, expected: 0},
		{name: "empty string", raw: `""`, expected: 0},
		{name: "whitespace only", raw: `" "`, expected: 0},
		{name: "not a number", raw: `"sometimes"`, wantErr: true},
		// A quoted value too large for the target must error rather than wrap
		// to a small or negative number, which would read as a real setting.
		{name: "quoted overflow", raw: `"99999999999999999999"`, wantErr: true},
		{name: "bare overflow", raw: `99999999999999999999`, wantErr: true},
		{name: "quoted float", raw: `"1.5"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got firefoxFlexInt
			err := json.Unmarshal([]byte(tt.raw), &got)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, int(got))
		})
	}
}
