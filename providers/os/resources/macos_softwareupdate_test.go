// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// =============================================================================
// parseSoftwareUpdatePrefs — plist key mapping
// =============================================================================

func TestParseSoftwareUpdatePrefs_AllSet(t *testing.T) {
	d := map[string]any{
		"AutomaticCheckEnabled":            true,
		"AutomaticDownload":                true,
		"AutomaticallyInstallMacOSUpdates": true,
		"ConfigDataInstall":                true,
		"CriticalUpdateInstall":            true,
		"LastSuccessfulDate":               "2024-08-12T14:23:00Z",
	}
	s := parseSoftwareUpdatePrefs(d)
	assertSetting(t, true, s.autoCheckEnabled)
	assertSetting(t, true, s.autoDownloadEnabled)
	assertSetting(t, true, s.autoInstallMacOSUpdates)
	assertSetting(t, true, s.installSystemDataFiles)
	assertSetting(t, true, s.installSecurityResponses)
	require.NotNil(t, s.lastSuccessfulCheck)
	expected, _ := time.Parse(time.RFC3339, "2024-08-12T14:23:00Z")
	assert.True(t, s.lastSuccessfulCheck.Equal(expected))
}

func TestParseSoftwareUpdatePrefs_AllUnset(t *testing.T) {
	// An absent key is unset, not false, so a lower-precedence source can answer.
	for name, d := range map[string]map[string]any{"empty": {}, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, softwareupdateSettings{}, parseSoftwareUpdatePrefs(d))
		})
	}
}

func TestParseSoftwareUpdatePrefs_MixedBoolEncodings(t *testing.T) {
	// `defaults write -int 1` and MDM-managed prefs both end up as
	// non-bool encodings. optBoolFromPlist normalizes all of them.
	d := map[string]any{
		"AutomaticCheckEnabled":            float64(1),
		"AutomaticDownload":                int64(0),
		"AutomaticallyInstallMacOSUpdates": "true",
		"ConfigDataInstall":                "1",
		"CriticalUpdateInstall":            "false",
	}
	s := parseSoftwareUpdatePrefs(d)
	assertSetting(t, true, s.autoCheckEnabled, "float64(1) is truthy")
	assertSetting(t, false, s.autoDownloadEnabled, "int64(0) is falsy")
	assertSetting(t, true, s.autoInstallMacOSUpdates, `"true" is truthy`)
	assertSetting(t, true, s.installSystemDataFiles, `"1" is truthy`)
	assertSetting(t, false, s.installSecurityResponses, `"false" is falsy`)
}

// =============================================================================
// parseSoftwareUpdateDDMState — persisted DDM declaration
// =============================================================================

func decodeSoftwareUpdateFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/macos-softwareupdate/" + name)
	require.NoError(t, err)
	d, err := plist.Decode(bytes.NewReader(raw))
	require.NoError(t, err)
	return d
}

// The fixtures have the shape macOS writes to
// /private/var/db/softwareupdate/SoftwareUpdateDDMStatePersistence.plist,
// with a placeholder declaration identifier. macOS writes the file as a binary
// plist; the fixtures are its XML form so they can be read in review.
func TestParseSoftwareUpdateDDMState(t *testing.T) {
	// Measured: macOS 26.7.3 (25G342) with a software update settings
	// declaration forcing automatic download on, 2026-11-12. The key path and
	// the integer 1 were read with `plutil -p`.
	t.Run("AlwaysOn download, install keys Allowed", func(t *testing.T) {
		s := parseSoftwareUpdateDDMState(decodeSoftwareUpdateFixture(t, "ddm-state-always-on.plist"))
		assertSetting(t, true, s.autoDownloadEnabled)
		assert.Nil(t, s.autoInstallMacOSUpdates, "Allowed leaves the key unset")
		assert.Nil(t, s.installSystemDataFiles)
		assert.Nil(t, s.installSecurityResponses)
		assert.Nil(t, s.autoCheckEnabled, "the declaration has no check setting")
		assert.Nil(t, s.lastSuccessfulCheck)
	})

	// Synthetic: every setting forced off, stored as 0, and the two install
	// key names; no target showed this.
	t.Run("AlwaysOff", func(t *testing.T) {
		s := parseSoftwareUpdateDDMState(decodeSoftwareUpdateFixture(t, "ddm-state-always-off.plist"))
		assertSetting(t, false, s.autoDownloadEnabled)
		assertSetting(t, false, s.autoInstallMacOSUpdates)
		assertSetting(t, false, s.installSystemDataFiles, "InstallSecurityUpdate covers system data files")
		assertSetting(t, false, s.installSecurityResponses, "InstallSecurityUpdate covers Security Responses")
	})

	// Synthetic: a declaration that leaves every setting to the user, stored
	// as absent keys; no target showed this.
	t.Run("all Allowed", func(t *testing.T) {
		s := parseSoftwareUpdateDDMState(decodeSoftwareUpdateFixture(t, "ddm-state-allowed.plist"))
		assert.Equal(t, softwareupdateSettings{}, s)
	})
}

// Synthetic: shapes the undocumented file could take; no target showed these.
func TestParseSoftwareUpdateDDMState_UnexpectedShapes(t *testing.T) {
	for name, d := range map[string]map[string]any{
		"nil":                nil,
		"empty":              {},
		"no policy fields":   {"SUCorePersistedStateCoreVersion": "2.1.0"},
		"policy not a dict":  {"SUCorePersistedStatePolicyFields": "x"},
		"no global settings": {"SUCorePersistedStatePolicyFields": map[string]any{}},
		"unknown enum value": {"SUCorePersistedStatePolicyFields": map[string]any{
			"SUCoreDDMDeclarationGlobalSettings": map[string]any{"automaticallyDownload": float64(2)},
		}},
		"string value": {"SUCorePersistedStatePolicyFields": map[string]any{
			"SUCoreDDMDeclarationGlobalSettings": map[string]any{"automaticallyDownload": "AlwaysOn"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, softwareupdateSettings{}, parseSoftwareUpdateDDMState(d))
		})
	}
}

// =============================================================================
// mergeSoftwareUpdateSettings — per-key precedence
// =============================================================================

// Synthetic: the preference values are invented to exercise precedence. Only
// the always-on DDM fixture is measured.
func TestMergeSoftwareUpdateSettings(t *testing.T) {
	lastCheck := time.Date(2026, 11, 10, 14, 17, 58, 0, time.UTC)
	localPrefs := map[string]any{
		"AutomaticDownload":     false,
		"CriticalUpdateInstall": true,
		"LastSuccessfulDate":    lastCheck.Format(time.RFC3339),
	}

	t.Run("DDM declaration with no preference keys", func(t *testing.T) {
		ddm := decodeSoftwareUpdateFixture(t, "ddm-state-always-on.plist")
		s := mergeSoftwareUpdateSettings(
			parseSoftwareUpdateDDMState(ddm),
			parseSoftwareUpdatePrefs(nil),
			parseSoftwareUpdatePrefs(map[string]any{"LastSessionSuccessful": true}),
		)
		assertSetting(t, true, s.autoDownloadEnabled)
	})

	t.Run("DDM declaration overrides managed and local preferences", func(t *testing.T) {
		ddm := decodeSoftwareUpdateFixture(t, "ddm-state-always-off.plist")
		s := mergeSoftwareUpdateSettings(
			parseSoftwareUpdateDDMState(ddm),
			parseSoftwareUpdatePrefs(map[string]any{"AutomaticDownload": true}),
			parseSoftwareUpdatePrefs(localPrefs),
		)
		assertSetting(t, false, s.autoDownloadEnabled)
		assertSetting(t, false, s.installSecurityResponses)
	})

	t.Run("partial profile leaves other keys to local preferences", func(t *testing.T) {
		s := mergeSoftwareUpdateSettings(
			parseSoftwareUpdateDDMState(nil),
			parseSoftwareUpdatePrefs(map[string]any{"AutomaticCheckEnabled": true}),
			parseSoftwareUpdatePrefs(localPrefs),
		)
		assertSetting(t, true, s.autoCheckEnabled)
		assertSetting(t, false, s.autoDownloadEnabled, "local preference is not hidden by the profile")
		assertSetting(t, true, s.installSecurityResponses)
		require.NotNil(t, s.lastSuccessfulCheck, "LastSuccessfulDate is only ever in local preferences")
		assert.True(t, s.lastSuccessfulCheck.Equal(lastCheck))
	})

	t.Run("managed profile overrides local preferences", func(t *testing.T) {
		s := mergeSoftwareUpdateSettings(
			parseSoftwareUpdatePrefs(map[string]any{"AutomaticDownload": true}),
			parseSoftwareUpdatePrefs(localPrefs),
		)
		assertSetting(t, true, s.autoDownloadEnabled)
	})

	t.Run("nothing set", func(t *testing.T) {
		s := mergeSoftwareUpdateSettings(
			parseSoftwareUpdateDDMState(nil),
			parseSoftwareUpdatePrefs(nil),
			parseSoftwareUpdatePrefs(nil),
		)
		assert.Equal(t, softwareupdateSettings{}, s)
	})
}

// =============================================================================
// optBoolFromPlist / ddmSettingFromPlist / timeFromPlist
// =============================================================================

func TestOptBoolFromPlist(t *testing.T) {
	d := map[string]any{
		"realBool":  true,
		"falseBool": false,
		"float1":    float64(1),
		"float0":    float64(0),
		"intTrue":   int64(1),
		"intFalse":  int64(0),
		"strTrue":   "true",
		"strTRUE":   "TRUE",
		"strFalse":  "false",
		"str1":      "1",
		"str0":      "0",
		"strJunk":   "maybe",
		"junk":      []string{"not", "a", "bool"},
		"nil":       nil,
	}
	assertSetting(t, true, optBoolFromPlist(d, "realBool"))
	assertSetting(t, false, optBoolFromPlist(d, "falseBool"), "an explicit false is a value")
	assertSetting(t, true, optBoolFromPlist(d, "float1"))
	assertSetting(t, false, optBoolFromPlist(d, "float0"))
	assertSetting(t, true, optBoolFromPlist(d, "intTrue"))
	assertSetting(t, false, optBoolFromPlist(d, "intFalse"))
	assertSetting(t, true, optBoolFromPlist(d, "strTrue"))
	assertSetting(t, true, optBoolFromPlist(d, "strTRUE"), "case-insensitive string match")
	assertSetting(t, false, optBoolFromPlist(d, "strFalse"))
	assertSetting(t, true, optBoolFromPlist(d, "str1"))
	assertSetting(t, false, optBoolFromPlist(d, "str0"))
	assert.Nil(t, optBoolFromPlist(d, "strJunk"), "unrecognised string is unset")
	assert.Nil(t, optBoolFromPlist(d, "junk"), "unknown shape is unset, not false")
	assert.Nil(t, optBoolFromPlist(d, "nil"), "nil value is unset")
	assert.Nil(t, optBoolFromPlist(d, "missing"), "absent key is unset")
}

func TestDDMSettingFromPlist(t *testing.T) {
	d := map[string]any{
		"alwaysOn":  float64(1),
		"alwaysOff": float64(0),
		"unknown":   float64(2),
		"bool":      true,
		"string":    "AlwaysOn",
	}
	assertSetting(t, true, ddmSettingFromPlist(d, "alwaysOn"))
	assertSetting(t, false, ddmSettingFromPlist(d, "alwaysOff"))
	assert.Nil(t, ddmSettingFromPlist(d, "unknown"), "an enum value macOS does not write is not guessed at")
	assertSetting(t, true, ddmSettingFromPlist(d, "bool"))
	assert.Nil(t, ddmSettingFromPlist(d, "string"))
	assert.Nil(t, ddmSettingFromPlist(d, "missing"), "Allowed is stored as an absent key")
}

func assertSetting(t *testing.T, want bool, got *bool, msgAndArgs ...any) {
	t.Helper()
	if assert.NotNil(t, got, msgAndArgs...) {
		assert.Equal(t, want, *got, msgAndArgs...)
	}
}

func TestTimeFromPlist(t *testing.T) {
	d := map[string]any{
		"good":  "2024-08-12T14:23:00Z",
		"nano":  "2024-08-12T14:23:00.123456789Z",
		"empty": "",
		"junk":  "not-a-timestamp",
		"wrong": 42,
	}
	got := timeFromPlist(d, "good")
	require.NotNil(t, got)
	expected, _ := time.Parse(time.RFC3339, "2024-08-12T14:23:00Z")
	assert.True(t, got.Equal(expected))

	gotNano := timeFromPlist(d, "nano")
	require.NotNil(t, gotNano, "nanosecond precision still parses")

	assert.Nil(t, timeFromPlist(d, "empty"), "empty string is nil")
	assert.Nil(t, timeFromPlist(d, "junk"), "unparseable value is nil")
	assert.Nil(t, timeFromPlist(d, "wrong"), "non-string value is nil")
	assert.Nil(t, timeFromPlist(d, "missing"), "absent key is nil")
}

// =============================================================================
// parseSoftwareUpdateList — softwareupdate -l output
// =============================================================================

func TestParseSoftwareUpdateList_NoUpdates(t *testing.T) {
	in := `Software Update Tool

Finding available software
No new software available.
`
	got := parseSoftwareUpdateList(in)
	assert.Empty(t, got)
}

func TestParseSoftwareUpdateList_TwoUpdates(t *testing.T) {
	in := "Software Update Tool\n" +
		"\n" +
		"Finding available software\n" +
		"Software Update found the following new or updated software:\n" +
		"* Label: macOS Sonoma 14.5-23F79\n" +
		"\tTitle: macOS Sonoma 14.5, Version: 14.5, Size: 7180348K, Recommended: YES, Action: restart,\n" +
		"* Label: Safari17.5MajorSU-17.5\n" +
		"\tTitle: Safari, Version: 17.5, Size: 138648K, Recommended: YES,\n"

	got := parseSoftwareUpdateList(in)
	require.Len(t, got, 2)

	macOS := got[0]
	assert.Equal(t, "macOS Sonoma 14.5-23F79", macOS.label)
	assert.Equal(t, "macOS Sonoma 14.5", macOS.title)
	assert.Equal(t, "14.5", macOS.version)
	assert.Equal(t, int64(7180348), macOS.size, "Size: 7180348K parses to 7180348 KiB")
	assert.True(t, macOS.recommended)
	assert.Equal(t, "restart", macOS.action, "macOS updates need a restart")

	safari := got[1]
	assert.Equal(t, "Safari17.5MajorSU-17.5", safari.label)
	assert.Equal(t, "Safari", safari.title)
	assert.Equal(t, "17.5", safari.version)
	assert.Equal(t, int64(138648), safari.size)
	assert.True(t, safari.recommended)
	assert.Equal(t, "", safari.action, "Safari update doesn't need a restart")
}

func TestParseSoftwareUpdateList_NonRecommendedAndMissingFields(t *testing.T) {
	// Older / niche updates can come back without all fields and with
	// Recommended: NO. Both shapes must parse cleanly.
	in := "* Label: SomeOptional-1.0\n" +
		"\tTitle: Some Optional, Version: 1.0, Recommended: NO,\n"
	got := parseSoftwareUpdateList(in)
	require.Len(t, got, 1)
	assert.Equal(t, "SomeOptional-1.0", got[0].label)
	assert.Equal(t, "Some Optional", got[0].title)
	assert.Equal(t, "1.0", got[0].version)
	assert.Equal(t, int64(0), got[0].size, "missing Size stays at zero value")
	assert.False(t, got[0].recommended)
	assert.Equal(t, "", got[0].action)
}

func TestParseSoftwareUpdateList_UnknownMetadataIgnored(t *testing.T) {
	// macOS versions sometimes add new metadata keys (Build, Type, ...).
	// They must be ignored rather than poisoning the entry.
	in := "* Label: Future-1.0\n" +
		"\tTitle: Future Update, Version: 1.0, Build: 23A123, Type: Recommended, Size: 100K, Recommended: YES,\n"
	got := parseSoftwareUpdateList(in)
	require.Len(t, got, 1)
	assert.Equal(t, "Future-1.0", got[0].label)
	assert.Equal(t, "Future Update", got[0].title)
	assert.Equal(t, "1.0", got[0].version)
	assert.Equal(t, int64(100), got[0].size)
	assert.True(t, got[0].recommended)
}

func TestParseSoftwareUpdateList_LabelWithSpaces(t *testing.T) {
	// Labels themselves can contain spaces (e.g. `macOS Sonoma 14.5-23F79`).
	// The label runs from "* Label: " to end-of-line; the parser must
	// keep all of it.
	in := "* Label: macOS Big Sur 11.7.10-20G1427\n" +
		"\tTitle: macOS Big Sur 11.7.10, Version: 11.7.10, Recommended: YES,\n"
	got := parseSoftwareUpdateList(in)
	require.Len(t, got, 1)
	assert.Equal(t, "macOS Big Sur 11.7.10-20G1427", got[0].label)
}

func TestParseSoftwareUpdateList_OrphanMetadataIgnored(t *testing.T) {
	// Metadata-shaped lines without a preceding `* Label:` get dropped
	// rather than creating a phantom entry.
	in := "Software Update Tool\n" +
		"\tTitle: Orphan, Version: 1.0,\n" +
		"No new software available.\n"
	got := parseSoftwareUpdateList(in)
	assert.Empty(t, got)
}

func TestParseSoftwareUpdateList_Empty(t *testing.T) {
	assert.Empty(t, parseSoftwareUpdateList(""))
}

// =============================================================================
// parseSoftwareUpdateSize
// =============================================================================

func TestParseSoftwareUpdateSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"7180348K", 7180348},
		{"138648K", 138648},
		{"100k", 100},       // tolerate lowercase
		{" 100K ", 100},     // tolerate surrounding whitespace
		{"100", 100},        // tolerate missing suffix
		{"", 0},             // missing size
		{"K", 0},            // suffix only
		{"not-a-number", 0}, // garbage
		{"1234567890123", 1234567890123},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, parseSoftwareUpdateSize(tc.in), "input: %q", tc.in)
	}
}

// =============================================================================
// isSoftwareUpdateNoUpdatesSignal
// =============================================================================

func TestIsSoftwareUpdateNoUpdatesSignal(t *testing.T) {
	assert.True(t, isSoftwareUpdateNoUpdatesSignal("No new software available.\n", ""))
	assert.True(t, isSoftwareUpdateNoUpdatesSignal("", "No updates available.\n"))
	assert.True(t, isSoftwareUpdateNoUpdatesSignal("", "NO NEW SOFTWARE AVAILABLE"), "case-insensitive")
	assert.False(t, isSoftwareUpdateNoUpdatesSignal("", "Permission denied"))
	assert.False(t, isSoftwareUpdateNoUpdatesSignal("", "softwareupdate: catalog unreachable"))
	assert.False(t, isSoftwareUpdateNoUpdatesSignal("", ""), "blank output is not a no-updates signal")
}

// =============================================================================
// stripPrefix
// =============================================================================

func TestStripPrefix(t *testing.T) {
	rest, ok := stripPrefix("* Label: foo", "* Label:")
	assert.True(t, ok)
	assert.Equal(t, " foo", rest)

	rest, ok = stripPrefix("Title: x", "* Label:")
	assert.False(t, ok)
	assert.Equal(t, "Title: x", rest)

	rest, ok = stripPrefix("", "* Label:")
	assert.False(t, ok)
	assert.Equal(t, "", rest)
}

func TestParseSoftwareUpdateSchedule(t *testing.T) {
	for name, tt := range map[string]struct {
		stdout string
		want   bool
		ok     bool
	}{
		"on":           {"Automatic checking for updates is turned on\n", true, true},
		"off":          {"Automatic checking for updates is turned off\n", false, true},
		"unrecognised": {"softwareupdate: unknown option\n", false, false},
		"empty":        {"", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			v, ok := parseSoftwareUpdateSchedule(tt.stdout)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.want, v)
			}
		})
	}
}
