// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// parseSoftwareUpdateSettings — plist key mapping
// =============================================================================

func TestParseSoftwareUpdateSettings_AllSet(t *testing.T) {
	d := map[string]any{
		"AutomaticCheckEnabled":            true,
		"AutomaticDownload":                true,
		"AutomaticallyInstallMacOSUpdates": true,
		"ConfigDataInstall":                true,
		"CriticalUpdateInstall":            true,
		"LastSuccessfulDate":               "2024-08-12T14:23:00Z",
	}
	s := parseSoftwareUpdateSettings(d)
	assert.True(t, s.autoCheckEnabled)
	assert.True(t, s.autoDownloadEnabled)
	assert.True(t, s.autoInstallMacOSUpdates)
	assert.True(t, s.installSystemDataFiles)
	assert.True(t, s.installSecurityResponses)
	require.NotNil(t, s.lastSuccessfulCheck)
	expected, _ := time.Parse(time.RFC3339, "2024-08-12T14:23:00Z")
	assert.True(t, s.lastSuccessfulCheck.Equal(expected))
}

func TestParseSoftwareUpdateSettings_AllUnset(t *testing.T) {
	// Empty plist means no policy has ever been written. All boolean
	// fields read false — auditors should fail soft for un-policied devices.
	s := parseSoftwareUpdateSettings(map[string]any{})
	assert.False(t, s.autoCheckEnabled)
	assert.False(t, s.autoDownloadEnabled)
	assert.False(t, s.autoInstallMacOSUpdates)
	assert.False(t, s.installSystemDataFiles)
	assert.False(t, s.installSecurityResponses)
	assert.Nil(t, s.lastSuccessfulCheck, "missing LastSuccessfulDate stays nil")
}

func TestParseSoftwareUpdateSettings_MixedBoolEncodings(t *testing.T) {
	// `defaults write -int 1` and MDM-managed prefs both end up as
	// non-bool encodings. boolFromPlist normalizes all of them.
	d := map[string]any{
		"AutomaticCheckEnabled":            float64(1),
		"AutomaticDownload":                int64(0),
		"AutomaticallyInstallMacOSUpdates": "true",
		"ConfigDataInstall":                "1",
		"CriticalUpdateInstall":            "false",
	}
	s := parseSoftwareUpdateSettings(d)
	assert.True(t, s.autoCheckEnabled, "float64(1) is truthy")
	assert.False(t, s.autoDownloadEnabled, "int64(0) is falsy")
	assert.True(t, s.autoInstallMacOSUpdates, `"true" is truthy`)
	assert.True(t, s.installSystemDataFiles, `"1" is truthy`)
	assert.False(t, s.installSecurityResponses, `"false" is falsy`)
}

// =============================================================================
// boolFromPlist / timeFromPlist
// =============================================================================

func TestBoolFromPlist(t *testing.T) {
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
		"junk":      []string{"not", "a", "bool"},
	}
	assert.True(t, boolFromPlist(d, "realBool"))
	assert.False(t, boolFromPlist(d, "falseBool"))
	assert.True(t, boolFromPlist(d, "float1"))
	assert.False(t, boolFromPlist(d, "float0"))
	assert.True(t, boolFromPlist(d, "intTrue"))
	assert.False(t, boolFromPlist(d, "intFalse"))
	assert.True(t, boolFromPlist(d, "strTrue"))
	assert.True(t, boolFromPlist(d, "strTRUE"), "case-insensitive string match")
	assert.False(t, boolFromPlist(d, "strFalse"))
	assert.True(t, boolFromPlist(d, "str1"))
	assert.False(t, boolFromPlist(d, "junk"), "unknown shape is false, not panic")
	assert.False(t, boolFromPlist(d, "missing"), "absent key is false")
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

// AutomaticCheckEnabled is only written once someone changes the setting.
// Its absence is not "off" -- automatic checking is on by default -- so the
// key's presence has to be distinguished from its value.
func TestKeyPresentInPlist(t *testing.T) {
	d := map[string]any{
		"AutomaticDownload": float64(1),
		"ExplicitFalse":     false,
		"ExplicitNil":       nil,
	}
	assert.True(t, keyPresentInPlist(d, "AutomaticDownload"))
	assert.True(t, keyPresentInPlist(d, "ExplicitFalse"), "an explicit false is still a written key")
	assert.False(t, keyPresentInPlist(d, "ExplicitNil"))
	assert.False(t, keyPresentInPlist(d, "AutomaticCheckEnabled"))
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
