// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLooksLikeVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
		reason  string
	}{
		// Every accepted case below was read off a real Mac's
		// `system_profiler SPApplicationsDataType` output.
		{"10.0", true, "Preview"},
		{"128.12.0", true, "Firefox"},
		{"154.0.8037.45", true, "Google Chrome, four components"},
		{"v2.0.6", true, "Raspberry Pi Imager ships a leading v"},
		{"1.0 (1234)", true, "build number in parentheses is decoration after the version"},
		{"3.2 beta 4", true, "pre-release decoration after the version"},

		// The bug this guard exists for.
		{"Windows 11", false, "guest OS name where a version belongs"},
		{"Windows 11 Pro", false, "same, with an edition"},

		// A version has to be there at all. An empty string is not rejected
		// here so much as handled by the caller, which treats it as "ask the
		// Info.plist" exactly as it did before this check existed.
		{"", false, "no version reported"},
		{"unknown", false, "a word, not a version"},
		{"Version 2.0", false, "the number is behind a word"},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			assert.Equal(t, test.want, looksLikeVersion(test.version), test.reason)
		})
	}
}

func TestStripVersionLabel(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		// OpenRA ships all three games with both version keys set to the
		// release tag, read off a real Mac.
		{"release tag", "release-20250330", "20250330"},
		{"version word", "Version 2.0", "2.0"},
		{"label is case-insensitive", "RELEASE_1.4.2", "1.4.2"},
		{"label before a v-prefixed version", "release-v2.0.6", "v2.0.6"},

		// A word in front of a number that names something other than the
		// version stays as it is, so looksLikeVersion still rejects it.
		{"guest OS name", "Windows 11", "Windows 11"},
		{"build number", "Build 2079", "Build 2079"},
		{"channel prefix", "EAP GO-262.6228.35", "EAP GO-262.6228.35"},
		{"OpenRA playtest channel", "playtest-20250302", "playtest-20250302"},

		// The label alone, or followed by something that is not a version.
		{"label without a version", "release", "release"},
		{"label before a word", "Version unknown", "Version unknown"},
		{"label fused to the word", "release20250330", "release20250330"},

		// Already a version, so there is nothing to strip.
		{"clean version", "1.2.6", "1.2.6"},
		{"empty", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, stripVersionLabel(test.version))
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		// The reported bug. Adobe ships both the Acrobat updater and its helper
		// with a padded CFBundleShortVersionString.
		{"padded separators", "1 . 2 . 6", "1.2.6"},
		{"padded separators, two components", "1 . 2", "1.2"},
		{"padding on one side only", "10.15 .3", "10.15.3"},
		{"tab padding", "1\t.\t2\t.\t6", "1.2.6"},
		{"multi-component build number", "26 . 001 . 21789", "26.001.21789"},

		// Already clean, so there is nothing to do.
		{"clean version", "1.2.6", "1.2.6"},
		{"single component", "607", "607"},
		{"empty", "", ""},

		// Whitespace in a macOS version is usually a second field rather than
		// padding, and fusing the two would invent a version no vendor ships.
		// Every one of these was read off a real Mac.
		{"build number in parentheses", "7.1.5 (84650)", "7.1.5 (84650)"},
		{"commit hash in parentheses", "1.2.1 (9c6d41e)", "1.2.1 (9c6d41e)"},
		{"build only", "Build 2079", "Build 2079"},
		{"version word prefix", "Version 2.0", "Version 2.0"},
		{"channel prefix", "EAP GO-262.6228.35", "EAP GO-262.6228.35"},
		{"vendor prefix", "ad 9.0.14", "ad 9.0.14"},

		// Observed on Windows assets, which share the Package struct. A service
		// pack or patch level is a component of the version, not padding.
		{"patch level suffix", "8.00 PL12", "8.00 PL12"},
		{"service pack suffix", "V14 SP1", "V14 SP1"},
		{"compilation suffix", "7.70 Compilation 1", "7.70 Compilation 1"},
		{"date prefixed driver version", "05/05/2017 10.46.0.0", "05/05/2017 10.46.0.0"},

		// looksLikeVersion drops a hypervisor launcher stub that reports the
		// guest OS where a version belongs. normalizeVersion must not turn one
		// into something version-shaped on the way past.
		{"guest OS name", "Windows 11", "Windows 11"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, normalizeVersion(test.version))
		})
	}
}
