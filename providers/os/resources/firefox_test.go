// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
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
	assert.Equal(t, 1, ublock.ApplyBackgroundUpdates)

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
	assert.Equal(t, 0, disabled.ApplyBackgroundUpdates)
	assert.False(t, disabled.ApplyBackgroundUpdates != 0) // autoupdate = false
	assert.Nil(t, disabled.UserPermissions)               // no userPermissions field

	// Test app-disabled addon
	appDisabled := data.Addons[2]
	assert.False(t, appDisabled.UserDisabled)
	assert.True(t, appDisabled.AppDisabled)
	assert.True(t, appDisabled.UserDisabled || appDisabled.AppDisabled) // disabled = true
	assert.Equal(t, 2, appDisabled.ApplyBackgroundUpdates)
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
			assert.Equal(t, tt.exists, firefoxBrowserDirExists(afs, tt.dir))
		})
	}
}
