// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mql

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLatestVersion(t *testing.T) {
	client := &http.Client{}
	version, err := GetLatestVersion(client)

	assert.NoError(t, err)
	assert.NotNil(t, version)
	assert.Equal(t, "https://install.mondoo.com/package/mql/latest.json", mqlLatestReleaseUrl)
}

// GetCoreVersion reads the ldflag-stamped Version, which the release flow sets
// to whatever `git describe` returns - a `v`-prefixed tag. The core regex used
// to be anchored without that prefix, so every stamped build failed to match and
// fell through to the unstamped fallback, reporting the dev line instead of its
// own version.
func TestGetCoreVersion(t *testing.T) {
	original := Version
	defer func() { Version = original }()

	for _, test := range []struct {
		version  string
		expected string
	}{
		{"v13.53.4+1234", "13.53.4"},
		{"13.53.4+1234", "13.53.4"},
		{"v13.53.4", "13.53.4"},
		{"13.53.4", "13.53.4"},

		// no version stamped, and anything that is not a version at all
		{"", devCoreVersion},
		{"not-a-version", devCoreVersion},
		{"rolling", devCoreVersion},
	} {
		t.Run(test.version, func(t *testing.T) {
			Version = test.version
			assert.Equal(t, test.expected, GetCoreVersion())
		})
	}
}

// An unstamped build has to report a version that orders at or above its own
// line, so the marker rides in the build-metadata slot after `+`. Ordering
// ignores build metadata; the `-` slot would sort it behind the release.
func TestDevVersion(t *testing.T) {
	original := Version
	defer func() { Version = original }()

	Version = ""
	assert.Equal(t, devVersion, GetVersion())
	assert.Contains(t, devVersion, "+rolling")
	assert.NotContains(t, devVersion, "-rolling")
}
