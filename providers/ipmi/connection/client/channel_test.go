// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeChannelInfo(t *testing.T) {
	// Channel 1, 802.3 LAN, IPMB-1.0 protocol, multi-session with 2 active
	// sessions. The reserved high bits of each byte are set to prove they
	// are masked off rather than folded into the value.
	info, err := decodeChannelInfo([]byte{0xf1, 0x84, 0xe1, 0x82, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	assert.Equal(t, int64(1), info.ID)
	assert.Equal(t, "802.3-lan", info.MediumType)
	assert.Equal(t, "ipmb-1.0", info.ProtocolType)
	assert.Equal(t, "multi-session", info.SessionSupport)
	assert.Equal(t, int64(2), info.ActiveSessionCount)
}

func TestDecodeChannelInfoShort(t *testing.T) {
	_, err := decodeChannelInfo([]byte{0x01, 0x04, 0x01})
	require.Error(t, err)
}

func TestDecodeChannelAuthCapabilities(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want ChannelAuthCapabilities
	}{
		{
			// Authentication type support 0xb5: extended data available
			// (bit 7), OEM (bit 5), password (bit 4), md5 (bit 2), none
			// (bit 0). Status 0x00: no bit set, so both authentication
			// protections are on and no null login is enabled.
			name: "hardened v2.0 channel",
			data: []byte{0x01, 0xb5, 0x00, 0x02},
			want: ChannelAuthCapabilities{
				AuthTypes:                       []string{"none", "md5", "password", "oem"},
				PerMessageAuthenticationEnabled: true,
				UserLevelAuthenticationEnabled:  true,
				SupportsIpmi20:                  true,
			},
		},
		{
			// Status 0x3f sets every reported bit: Kg non-default, both
			// authentication protections switched off, and all three
			// username states enabled.
			name: "anonymous login and authentication switched off",
			data: []byte{0x01, 0x81, 0x3f, 0x03},
			want: ChannelAuthCapabilities{
				AuthTypes:               []string{"none"},
				KgConfigured:            true,
				NonNullUsernamesEnabled: true,
				NullUsernamesEnabled:    true,
				AnonymousLoginEnabled:   true,
				SupportsIpmi15:          true,
				SupportsIpmi20:          true,
			},
		},
		{
			// Without the extended-data flag the fourth byte is reserved,
			// so neither connection-support bit may be reported even though
			// the byte carries 0x03.
			name: "v1.5 only channel ignores the extended byte",
			data: []byte{0x01, 0x15, 0x00, 0x03},
			want: ChannelAuthCapabilities{
				AuthTypes:                       []string{"none", "md5", "password"},
				PerMessageAuthenticationEnabled: true,
				UserLevelAuthenticationEnabled:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps, err := decodeChannelAuthCapabilities(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, *caps)
		})
	}
}

func TestDecodeChannelAuthCapabilitiesShort(t *testing.T) {
	_, err := decodeChannelAuthCapabilities([]byte{0x01, 0x15, 0x00})
	require.Error(t, err)
}

func TestDecodeChannelAccess(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want ChannelAccess
	}{
		{
			// Access mode 2 with the alerting bit clear.
			name: "always available with alerting on",
			data: []byte{0x02, 0x04},
			want: ChannelAccess{AccessMode: "always-available", PrivilegeLimit: "administrator", AlertingEnabled: true},
		},
		{
			// The alerting bit is set when alerting is switched off, so a
			// set bit must read as false.
			name: "alerting bit set means alerting off",
			data: []byte{0x22, 0x02},
			want: ChannelAccess{AccessMode: "always-available", PrivilegeLimit: "user", AlertingEnabled: false},
		},
		{
			name: "disabled channel with no access",
			data: []byte{0x20, 0x0f},
			want: ChannelAccess{AccessMode: "disabled", PrivilegeLimit: "no-access", AlertingEnabled: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access, err := decodeChannelAccess(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, *access)
		})
	}
}

func TestDecodeChannelAccessShort(t *testing.T) {
	_, err := decodeChannelAccess([]byte{0x02})
	require.Error(t, err)
}

func TestDecodePrivilegeLevel(t *testing.T) {
	// 0x00 is "the controller did not say" and 0x0f is an explicit refusal.
	// Collapsing either into the other would misreport the ceiling.
	assert.Equal(t, "unspecified", decodePrivilegeLevel(0x00))
	assert.Equal(t, "callback", decodePrivilegeLevel(0x01))
	assert.Equal(t, "user", decodePrivilegeLevel(0x02))
	assert.Equal(t, "operator", decodePrivilegeLevel(0x03))
	assert.Equal(t, "administrator", decodePrivilegeLevel(0x04))
	assert.Equal(t, "oem", decodePrivilegeLevel(0x05))
	assert.Equal(t, "no-access", decodePrivilegeLevel(0x0f))
	assert.Equal(t, "reserved", decodePrivilegeLevel(0x07))
}

func TestDecodeChannelMediumAndProtocol(t *testing.T) {
	assert.Equal(t, "802.3-lan", decodeChannelMedium(0x04))
	assert.Equal(t, "system-interface", decodeChannelMedium(0x0c))
	assert.Equal(t, "oem", decodeChannelMedium(0x60))
	assert.Equal(t, "oem", decodeChannelMedium(0x7f))
	assert.Equal(t, "reserved", decodeChannelMedium(0x80))
	assert.Equal(t, "kcs", decodeChannelProtocol(0x05))
	assert.Equal(t, "oem", decodeChannelProtocol(0x1c))
	assert.Equal(t, "reserved", decodeChannelProtocol(0x03))
}

func TestDecodeSessionSupport(t *testing.T) {
	assert.Equal(t, "session-less", decodeSessionSupport(0x0))
	assert.Equal(t, "single-session", decodeSessionSupport(0x1))
	assert.Equal(t, "multi-session", decodeSessionSupport(0x2))
	assert.Equal(t, "session-based", decodeSessionSupport(0x3))
}

func TestDecodeChannelAccessMode(t *testing.T) {
	assert.Equal(t, "disabled", decodeChannelAccessMode(0x0))
	assert.Equal(t, "pre-boot-only", decodeChannelAccessMode(0x1))
	assert.Equal(t, "always-available", decodeChannelAccessMode(0x2))
	assert.Equal(t, "shared", decodeChannelAccessMode(0x3))
	assert.Equal(t, "reserved", decodeChannelAccessMode(0x4))
}
