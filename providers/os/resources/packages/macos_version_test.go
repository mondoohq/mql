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
