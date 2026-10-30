// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

func TestOptionalTime(t *testing.T) {
	t.Run("nil while connected to control", func(t *testing.T) {
		// Tailscale omits lastSeen for a device that currently holds a
		// connection. Reporting null keeps a dormant-device query from
		// matching a device that is online right now.
		assert.Nil(t, optionalTime(nil))
	})

	t.Run("zero instant reads as absent", func(t *testing.T) {
		// Tailscale sends the zero instant for a key that never expires and
		// for a device with no creation date. Reporting it verbatim would
		// date the device to the year 1.
		assert.Nil(t, optionalTime(&tsclient.Time{}))
	})

	t.Run("returns the underlying instant", func(t *testing.T) {
		want := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
		got := optionalTime(&tsclient.Time{Time: want})
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})
}

// TestOptionalTime_AbsentTimestampEncodings covers the three ways Tailscale
// spells an absent timestamp, decoded through the SDK rather than constructed
// by hand, so the test still fails if the SDK changes how it unmarshals them.
func TestOptionalTime_AbsentTimestampEncodings(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"json null", `null`},
		{"empty string", `""`},
		{"zero instant", `"0001-01-01T00:00:00Z"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ts *tsclient.Time
			require.NoError(t, json.Unmarshal([]byte(tc.json), &ts))
			assert.Nil(t, optionalTime(ts))
		})
	}
}

// TestOptionalTime_KeyExpiryDisabledDeviceHasNoExpiry pins the behavior that
// motivated treating the zero instant as absent. A device whose key never
// expires must not satisfy a query for devices whose key has already expired.
func TestOptionalTime_KeyExpiryDisabledDeviceHasNoExpiry(t *testing.T) {
	// Shaped after the hello service device in the Tailscale SDK's own
	// devices.json fixture.
	const device = `{
		"id": "50052",
		"created": "",
		"expires": "0001-01-01T00:00:00Z",
		"keyExpiryDisabled": true,
		"isExternal": true
	}`

	var d tsclient.Device
	require.NoError(t, json.Unmarshal([]byte(device), &d))
	require.True(t, d.KeyExpiryDisabled)

	assert.Nil(t, optionalTime(&d.Expires),
		"a key set never to expire must not report an expiry in the year 1")
	assert.Nil(t, optionalTime(&d.Created),
		"a device with no creation date must not report one in the year 1")
}
