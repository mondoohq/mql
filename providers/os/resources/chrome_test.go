// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChromeTimeToGoTime(t *testing.T) {
	tests := []struct {
		name       string
		chromeTime string
		wantNil    bool
		wantYear   int
	}{
		{
			name:       "valid Chrome epoch time",
			chromeTime: "13345678901234567",
			wantNil:    false,
		},
		{
			name:       "empty string",
			chromeTime: "",
			wantNil:    true,
		},
		{
			name:       "zero value",
			chromeTime: "0",
			wantNil:    true,
		},
		{
			name:       "invalid string",
			chromeTime: "not-a-number",
			wantNil:    true,
		},
		{
			name:       "small value below Chrome epoch threshold",
			chromeTime: "12345",
			wantNil:    true,
		},
		{
			// 13300000000000000 microseconds since 1601-01-01
			// = 13300000000 seconds since 1601-01-01
			// = 13300000000 - 11644473600 = 1655526400 Unix time
			// = 2022-06-18 (approximately)
			name:       "known date conversion",
			chromeTime: "13300000000000000",
			wantNil:    false,
			wantYear:   2022,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := chromeTimeToGoTime(tt.chromeTime)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.True(t, result.After(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)),
					"converted time should be after year 2000, got %v", result)
				if tt.wantYear != 0 {
					assert.Equal(t, tt.wantYear, result.Year())
				}
			}
		})
	}
}

func TestResolveExtensionState(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name           string
		state          *int
		disableReasons json.RawMessage
		wantState      string
		wantEnabled    bool
	}{
		{"state 0 (disabled)", intPtr(0), nil, "disabled", false},
		{"state 1 (enabled)", intPtr(1), nil, "enabled", true},
		{"state 2 (unknown)", intPtr(2), nil, "unknown(2)", false},
		{"no state, disable_reasons=0", nil, json.RawMessage(`0`), "enabled", true},
		{"no state, disable_reasons=1 (int)", nil, json.RawMessage(`1`), "disabled", false},
		{"no state, disable_reasons=[8192] (array)", nil, json.RawMessage(`[8192]`), "disabled", false},
		{"no state, disable_reasons=[] (empty array)", nil, json.RawMessage(`[]`), "enabled", true},
		{"no state, no disable_reasons", nil, nil, "enabled", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, enabled := resolveExtensionState(tt.state, tt.disableReasons)
			assert.Equal(t, tt.wantState, state)
			assert.Equal(t, tt.wantEnabled, enabled)
		})
	}
}

func TestExtractChromeAuthor(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "string author",
			raw:      `"John Doe"`,
			expected: "John Doe",
		},
		{
			name:     "object with email",
			raw:      `{"email":"john@example.com"}`,
			expected: "john@example.com",
		},
		{
			name:     "empty raw",
			raw:      "",
			expected: "",
		},
		{
			name:     "null",
			raw:      "null",
			expected: "",
		},
		{
			name:     "empty string",
			raw:      `""`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw json.RawMessage
			if tt.raw != "" {
				raw = json.RawMessage(tt.raw)
			}
			assert.Equal(t, tt.expected, extractChromeAuthor(raw))
		})
	}
}

func TestMergeStringSlices(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []string
		expected []string
	}{
		{
			name:     "both empty",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name:     "only first",
			a:        []string{"a", "b"},
			b:        nil,
			expected: []string{"a", "b"},
		},
		{
			name:     "both non-empty",
			a:        []string{"storage", "tabs"},
			b:        []string{"https://*.google.com/*"},
			expected: []string{"storage", "tabs", "https://*.google.com/*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeStringSlices(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseChromePreferences(t *testing.T) {
	prefsJSON := `{
		"extensions": {
			"settings": {
				"aapbdbdomjkkjkaonfhkkikfgjllcleb": {
					"from_webstore": true,
					"install_time": "13300000000000000",
					"state": 1,
					"path": "aapbdbdomjkkjkaonfhkkikfgjllcleb/1.2.3_0",
					"manifest": {
						"name": "Test Extension",
						"version": "1.2.3",
						"description": "A test extension",
						"author": "Test Author",
						"manifest_version": 3,
						"permissions": ["storage", "tabs"],
						"host_permissions": ["https://*.google.com/*"],
						"optional_permissions": ["cookies"],
						"optional_host_permissions": ["https://*.example.com/*"],
						"update_url": "https://clients2.google.com/service/update2/crx",
						"default_locale": "en",
						"background": {
							"persistent": false
						},
						"content_scripts": [
							{
								"matches": ["https://mail.google.com/*", "https://inbox.google.com/*"],
								"js": ["inject.js", "helper.js"]
							}
						]
					}
				},
				"disabledext123456789012345678901": {
					"from_webstore": false,
					"install_time": "13300000000000000",
					"state": 0,
					"path": "disabledext123456789012345678901/2.0.0_0",
					"manifest": {
						"name": "Disabled Extension",
						"version": "2.0.0",
						"manifest_version": 2,
						"permissions": ["<all_urls>"],
						"background": {
							"persistent": true
						}
					}
				}
			}
		}
	}`

	var prefs chromePreferences
	err := json.Unmarshal([]byte(prefsJSON), &prefs)
	require.NoError(t, err)

	settings := prefs.Extensions.Settings
	require.Len(t, settings, 2)

	// Test the webstore extension
	ext := settings["aapbdbdomjkkjkaonfhkkikfgjllcleb"]
	assert.True(t, ext.FromWebstore)
	require.NotNil(t, ext.State)
	assert.Equal(t, 1, *ext.State)
	assert.Equal(t, "Test Extension", ext.Manifest.Name)
	assert.Equal(t, "1.2.3", ext.Manifest.Version)
	assert.Equal(t, 3, ext.Manifest.ManifestVersion)
	assert.Equal(t, []string{"storage", "tabs"}, rawMessagesToStrings(ext.Manifest.Permissions))
	assert.Equal(t, []string{"https://*.google.com/*"}, ext.Manifest.HostPermissions)
	assert.Equal(t, []string{"cookies"}, rawMessagesToStrings(ext.Manifest.OptionalPermissions))
	assert.Equal(t, []string{"https://*.example.com/*"}, ext.Manifest.OptionalHostPermissions)
	assert.Equal(t, "en", ext.Manifest.DefaultLocale)

	// Test merged permissions (V3: permissions + host_permissions)
	mergedPerms := mergeStringSlices(rawMessagesToStrings(ext.Manifest.Permissions), ext.Manifest.HostPermissions)
	assert.Equal(t, []string{"storage", "tabs", "https://*.google.com/*"}, mergedPerms)

	// Test merged optional permissions
	mergedOptPerms := mergeStringSlices(rawMessagesToStrings(ext.Manifest.OptionalPermissions), ext.Manifest.OptionalHostPermissions)
	assert.Equal(t, []string{"cookies", "https://*.example.com/*"}, mergedOptPerms)

	// Test author extraction
	author := extractChromeAuthor(ext.Manifest.Author)
	assert.Equal(t, "Test Author", author)

	// Test content scripts
	require.Len(t, ext.Manifest.ContentScripts, 1)
	cs := ext.Manifest.ContentScripts[0]
	assert.Equal(t, []string{"https://mail.google.com/*", "https://inbox.google.com/*"}, cs.Matches)
	assert.Equal(t, []string{"inject.js", "helper.js"}, cs.Js)

	// Content script denormalization: 2 scripts × 2 matches = 4 pairs
	pairCount := 0
	for _, script := range cs.Js {
		for _, match := range cs.Matches {
			pairCount++
			assert.NotEmpty(t, script)
			assert.NotEmpty(t, match)
		}
	}
	assert.Equal(t, 4, pairCount)

	// Test the disabled/sideloaded extension
	disabled := settings["disabledext123456789012345678901"]
	assert.False(t, disabled.FromWebstore)
	require.NotNil(t, disabled.State)
	assert.Equal(t, 0, *disabled.State)
	state, enabled := resolveExtensionState(disabled.State, disabled.DisableReasons)
	assert.Equal(t, "disabled", state)
	assert.False(t, enabled)
	assert.Equal(t, 2, disabled.Manifest.ManifestVersion)
	assert.Equal(t, []string{"<all_urls>"}, rawMessagesToStrings(disabled.Manifest.Permissions))
	require.NotNil(t, disabled.Manifest.Background)
	require.NotNil(t, disabled.Manifest.Background.Persistent)
	assert.True(t, *disabled.Manifest.Background.Persistent)
}

func TestComputeManifestHash(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}

	content := []byte(`{"name":"Test","version":"1.0"}`)
	expectedHash := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expectedHash[:])

	require.NoError(t, afs.WriteFile("/ext/manifest.json", content, 0644))

	hash := computeManifestHash(afs, "/ext")
	assert.Equal(t, expectedHex, hash)

	// Non-existent directory returns empty
	hash = computeManifestHash(afs, "/nonexistent")
	assert.Equal(t, "", hash)
}

func TestDiscoverChromeProfiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}

	// Create browser directory structure
	browserDir := "/home/user/.config/google-chrome"
	require.NoError(t, fs.MkdirAll(browserDir+"/Default", 0755))
	require.NoError(t, fs.MkdirAll(browserDir+"/Profile 1", 0755))
	require.NoError(t, fs.MkdirAll(browserDir+"/Profile 2", 0755))
	require.NoError(t, fs.MkdirAll(browserDir+"/Crashpad", 0755)) // not a profile

	// Add Preferences files to valid profiles
	require.NoError(t, afs.WriteFile(browserDir+"/Default/Preferences", []byte("{}"), 0644))
	require.NoError(t, afs.WriteFile(browserDir+"/Profile 1/Preferences", []byte("{}"), 0644))
	// Profile 2 has Extensions dir but no Preferences
	require.NoError(t, fs.MkdirAll(browserDir+"/Profile 2/Extensions", 0755))

	profiles := discoverChromeProfiles(afs, browserDir)
	assert.Contains(t, profiles, "Default")
	assert.Contains(t, profiles, "Profile 1")
	assert.Contains(t, profiles, "Profile 2") // has Extensions dir
	assert.NotContains(t, profiles, "Crashpad")
}

func TestResolveChromei18n(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}

	extDir := "/ext"
	messagesJSON := `{"appName":{"message":"My Extension"},"appDesc":{"message":"Does things"}}`
	require.NoError(t, fs.MkdirAll(extDir+"/_locales/en", 0755))
	require.NoError(t, afs.WriteFile(extDir+"/_locales/en/messages.json", []byte(messagesJSON), 0644))

	// Successful resolution
	result := resolveChromei18n(afs, extDir, "en", "__MSG_appName__")
	assert.Equal(t, "My Extension", result)

	// Case insensitive key lookup
	result = resolveChromei18n(afs, extDir, "en", "__MSG_APPNAME__")
	assert.Equal(t, "My Extension", result)

	// Non-existent message
	result = resolveChromei18n(afs, extDir, "en", "__MSG_nonexistent__")
	assert.Equal(t, "", result)

	// Not an i18n string
	result = resolveChromei18n(afs, extDir, "en", "Regular Name")
	assert.Equal(t, "", result)
}

// The two files below mirror a Google Chrome profile on Ubuntu 24.04: on
// Linux the extension entries live in Preferences, and Secure Preferences
// holds only the protection MAC.
const (
	linuxChromePreferences = `{"extensions":{"settings":{
"eimadpbcbfnmbkopoojfekhnkhdbieeh":{"from_webstore":true,"first_install_time":"13435385453500940","disable_reasons":[],"path":"eimadpbcbfnmbkopoojfekhnkhdbieeh/4.9.133_0","location":7,
 "manifest":{"name":"Dark Reader","version":"4.9.133","manifest_version":3,"permissions":["alarms","fontSettings","scripting","storage"],"host_permissions":["*://*/*"]}},
"mhjfbmdgcfjbbpaeojofohoefgiehjai":{"from_webstore":false,"first_install_time":"13435385452102160","disable_reasons":[],"path":"/opt/google/chrome/resources/pdf","location":5,
 "manifest":{"name":"Chrome PDF Viewer","version":"1","manifest_version":2}}}}}`
	linuxChromeSecurePreferences = `{"protection":{"super_mac":"33F663353631B144EA660B5F809D89BA41CAF954EE5776BE5004BB589CA96BE1"}}`
)

func TestLoadChromeExtensionSettingsLinuxLayout(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	profile := "/home/ubuntu/.config/google-chrome/Default"
	require.NoError(t, afs.WriteFile(profile+"/Preferences", []byte(linuxChromePreferences), 0o600))
	require.NoError(t, afs.WriteFile(profile+"/Secure Preferences", []byte(linuxChromeSecurePreferences), 0o600))

	settings, ok := loadChromeExtensionSettings(afs, profile)
	require.True(t, ok)
	require.Contains(t, settings, "eimadpbcbfnmbkopoojfekhnkhdbieeh")
	assert.Equal(t, "Dark Reader", settings["eimadpbcbfnmbkopoojfekhnkhdbieeh"].Manifest.Name)
	assert.Len(t, settings, 2)
}

func TestLoadChromeExtensionSettingsSecureWins(t *testing.T) {
	// Windows/macOS layout: Secure Preferences carries the authoritative entry,
	// Preferences may hold a stale or partial copy of the same extension.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	profile := "/p/Default"
	require.NoError(t, afs.WriteFile(profile+"/Preferences", []byte(`{"extensions":{"settings":{
"a":{"path":"a/1.0_0","manifest":{"name":"Old","version":"1.0"}},
"b":{"path":"b/2.0_0","manifest":{"name":"Only in Preferences","version":"2.0"}}}}}`), 0o600))
	require.NoError(t, afs.WriteFile(profile+"/Secure Preferences", []byte(`{"extensions":{"settings":{
"a":{"path":"a/1.1_0","manifest":{"name":"New","version":"1.1"}},
"b":{"active_permissions":{}}}}}`), 0o600))

	settings, ok := loadChromeExtensionSettings(afs, profile)
	require.True(t, ok)
	assert.Equal(t, "New", settings["a"].Manifest.Name)
	// A Secure Preferences entry without a manifest must not erase the
	// Preferences entry that has one.
	assert.Equal(t, "Only in Preferences", settings["b"].Manifest.Name)
}

func TestLoadChromeExtensionSettingsNoFiles(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	_, ok := loadChromeExtensionSettings(afs, "/p/Default")
	assert.False(t, ok)
}

func TestResolveExtensionDirAbsolutePaths(t *testing.T) {
	profile := "/home/ubuntu/.config/google-chrome/Default"
	assert.Equal(t, "/opt/google/chrome/resources/pdf",
		resolveExtensionDir(profile, "/opt/google/chrome/resources/pdf", "mhjfbmdgcfjbbpaeojofohoefgiehjai"))
	assert.Equal(t, `C:\Users\alice\unpacked-ext`,
		resolveExtensionDir(profile, `C:\Users\alice\unpacked-ext`, "x"))
	assert.Equal(t, profile+"/Extensions/eimadpbcbfnmbkopoojfekhnkhdbieeh/4.9.133_0",
		resolveExtensionDir(profile, "eimadpbcbfnmbkopoojfekhnkhdbieeh/4.9.133_0", "eimadpbcbfnmbkopoojfekhnkhdbieeh"))
}

func TestLoadChromeExtensionSettingsUnpackedReadsManifestFromDisk(t *testing.T) {
	// Chromium 154 on RHEL 9 started with --load-extension=/home/alice/unpacked-ext:
	// Chrome keeps no manifest copy in Preferences for unpacked (4) and
	// command-line (8) extensions, only the absolute directory they load from.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	profile := "/home/alice/.config/chromium/Default"
	require.NoError(t, afs.WriteFile(profile+"/Preferences", []byte(`{"extensions":{"settings":{
"hjbnjdnllbljlfnolgdgckpkkfkeadep":{"from_webstore":false,"first_install_time":"13435385453500940","disable_reasons":[],"location":8,"path":"/home/alice/unpacked-ext"},
"mhjfbmdgcfjbbpaeojofohoefgiehjai":{"location":5,"path":"/usr/lib64/chromium-browser/resources/pdf","manifest":{"name":"Chromium PDF Viewer","version":"1","manifest_version":2}},
"gone":{"location":4,"path":"/home/alice/deleted-ext"},
"internal":{"location":1,"path":"internal/1.0_0"}}}}`), 0o600))
	require.NoError(t, afs.WriteFile("/home/alice/unpacked-ext/manifest.json", []byte(`{"manifest_version": 3, "name": "Unpacked Test", "version": "0.0.1", "description": "local unpacked extension",
 "permissions": ["storage"], "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}]}`), 0o644))
	// A manifest beside an internal (web store) entry must not be read: its
	// path is relative to the profile's Extensions directory.
	require.NoError(t, afs.WriteFile("internal/1.0_0/manifest.json", []byte(`{"name":"wrong","version":"9"}`), 0o644))

	settings, ok := loadChromeExtensionSettings(afs, profile)
	require.True(t, ok)
	unpacked := settings["hjbnjdnllbljlfnolgdgckpkkfkeadep"]
	assert.Equal(t, "Unpacked Test", unpacked.Manifest.Name)
	assert.Equal(t, "0.0.1", unpacked.Manifest.Version)
	assert.Equal(t, 3, unpacked.Manifest.ManifestVersion)
	require.Len(t, unpacked.Manifest.ContentScripts, 1)
	assert.Equal(t, []string{"cs.js"}, unpacked.Manifest.ContentScripts[0].Js)
	assert.Equal(t, "Chromium PDF Viewer", settings["mhjfbmdgcfjbbpaeojofohoefgiehjai"].Manifest.Name)
	// The directory is gone: nothing to read, the entry stays without identity.
	assert.False(t, settings["gone"].Manifest.hasIdentity())
	assert.False(t, settings["internal"].Manifest.hasIdentity())
}
