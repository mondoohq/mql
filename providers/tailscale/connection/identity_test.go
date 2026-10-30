// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestDeviceIdFromAsset(t *testing.T) {
	tests := []struct {
		name  string
		asset *inventory.Asset
		want  string
	}{
		{name: "nil asset", asset: nil, want: ""},
		{name: "no platform ids", asset: &inventory.Asset{}, want: ""},
		{
			name:  "device asset",
			asset: &inventory.Asset{PlatformIds: []string{NewTailscaleDeviceIdentifier("nodeidCNTRL")}},
			want:  "nodeidCNTRL",
		},
		{
			name: "device id found among several platform ids",
			asset: &inventory.Asset{PlatformIds: []string{
				"//platformid.api.mondoo.app/runtime/other/thing",
				NewTailscaleDeviceIdentifier("12345"),
			}},
			want: "12345",
		},
		{
			// A user asset must not answer a device lookup: the two prefixes
			// are distinct and must not cross-match.
			name:  "user asset does not match",
			asset: &inventory.Asset{PlatformIds: []string{NewTailscaleUserIdentifier("uid-1")}},
			want:  "",
		},
		{
			// A prefix with nothing after it carries no id and must not be
			// injected, or it would defeat the init's own emptiness check.
			name:  "bare prefix yields nothing",
			asset: &inventory.Asset{PlatformIds: []string{PlatformIdTailscaleDevice}},
			want:  "",
		},
		{
			name:  "tailnet asset does not match",
			asset: &inventory.Asset{PlatformIds: []string{PlatformIdTailscaleTailnet + "example.com"}},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, DeviceIdFromAsset(tc.asset))
		})
	}
}

func TestUserIdFromAsset(t *testing.T) {
	tests := []struct {
		name  string
		asset *inventory.Asset
		want  string
	}{
		{name: "nil asset", asset: nil, want: ""},
		{name: "no platform ids", asset: &inventory.Asset{}, want: ""},
		{
			name:  "user asset",
			asset: &inventory.Asset{PlatformIds: []string{NewTailscaleUserIdentifier("uid-abc123")}},
			want:  "uid-abc123",
		},
		{
			name:  "device asset does not match",
			asset: &inventory.Asset{PlatformIds: []string{NewTailscaleDeviceIdentifier("12345")}},
			want:  "",
		},
		{
			name:  "bare prefix yields nothing",
			asset: &inventory.Asset{PlatformIds: []string{PlatformIdTailscaleUser}},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, UserIdFromAsset(tc.asset))
		})
	}
}

// TestIdentifierUsesExplicitTailnet covers the path that needs no API call:
// when the user names a tailnet, the asset identity is derived from it
// directly and two different tailnets cannot collide.
func TestIdentifierUsesExplicitTailnet(t *testing.T) {
	conn := &TailscaleConnection{
		Conf: &inventory.Config{Options: map[string]string{OPTION_TAILNET: "example.com"}},
	}
	assert.Equal(t, "example.com", conn.ResolveTailnet())
	assert.Equal(t, PlatformIdTailscaleTailnet+"example.com", conn.Identifier())

	other := &TailscaleConnection{
		Conf: &inventory.Config{Options: map[string]string{OPTION_TAILNET: "other.example.org"}},
	}
	assert.NotEqual(t, conn.Identifier(), other.Identifier())
}
