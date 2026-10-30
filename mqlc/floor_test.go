// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/mqlc"
)

// The default support window: two majors back, never below 14, always the .0.0
// of the oldest major it serves.
func TestDefaultDowngradeFloor(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"two back clamps to the stop floor", "15.1.2", "14.0.0"},
		{"two back is exactly the stop floor", "16.4.0", "14.0.0"},
		{"two back is above the stop floor", "17.1.2", "15.0.0"},
		{"far future", "23.0.1", "21.0.0"},
		// At 14 the window is the stop floor itself, which is still useful: a
		// field added in 14.5.0 can be served down to a 14.0.0 reader.
		{"the first major with the mechanism", "14.5.0", "14.0.0"},
		{"a leading v is tolerated", "v18.0.0", "16.0.0"},
		{"a bare major is tolerated", "18", "16.0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mqlc.DefaultDowngradeFloor(map[string]string{"os": tc.version})
			assert.Equal(t, map[string]string{"os": tc.want}, got)
		})
	}
}

// A provider below the stop floor gets no floor at all, not a floor above its
// own version. An unset floor is what keeps the compiler from starting that
// provider to fetch a catalog nothing could consume.
func TestDefaultDowngradeFloorSkipsProvidersBelowTheStopFloor(t *testing.T) {
	for _, version := range []string{"13.53.3", "13.0.0", "9.0.0", "0.1.0"} {
		assert.Nil(t, mqlc.DefaultDowngradeFloor(map[string]string{"os": version}), version)
	}
}

// A version we cannot read is skipped rather than guessed at: a wrong floor
// either withholds fallbacks that would have worked or emits ones that cannot.
func TestDefaultDowngradeFloorSkipsUnreadableVersions(t *testing.T) {
	for _, version := range []string{"", "   ", "unstable", "v", "notaversion", "-1.0.0"} {
		assert.Nil(t, mqlc.DefaultDowngradeFloor(map[string]string{"os": version}), version)
	}
	assert.Nil(t, mqlc.DefaultDowngradeFloor(nil))
	assert.Nil(t, mqlc.DefaultDowngradeFloor(map[string]string{}))
}

// The window is per provider, because providers version independently.
func TestDefaultDowngradeFloorIsPerProvider(t *testing.T) {
	got := mqlc.DefaultDowngradeFloor(map[string]string{
		"go.mondoo.com/mql/providers/os":  "17.1.2",
		"go.mondoo.com/mql/providers/aws": "15.0.0",
		"go.mondoo.com/mql/providers/gcp": "13.9.0", // below the stop floor
	})
	assert.Equal(t, map[string]string{
		"os":  "15.0.0",
		"aws": "14.0.0",
	}, got, "keys normalize to the stable provider name, and a pre-14 provider is left out")
}
