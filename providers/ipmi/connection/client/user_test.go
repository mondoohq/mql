// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeUserAccess(t *testing.T) {
	// Max user IDs 10, enable status 01b (enabled) with 3 enabled slots,
	// 2 fixed-name slots, and a slot that is callback-only, link-auth
	// enabled, messaging enabled at administrator privilege. The high bits
	// of the first three bytes are set to prove they are masked off.
	access, err := decodeUserAccess([]byte{0xca, 0x43, 0xc2, 0x74})
	require.NoError(t, err)
	assert.Equal(t, int64(10), access.MaxUserIDs)
	assert.Equal(t, uint8(0x01), access.EnableStatus)
	assert.Equal(t, int64(3), access.EnabledUserCount)
	assert.Equal(t, int64(2), access.FixedNameUserCount)
	assert.True(t, access.CallbackOnly)
	assert.True(t, access.LinkAuthenticationEnabled)
	assert.True(t, access.IpmiMessagingEnabled)
	assert.Equal(t, "administrator", access.PrivilegeLimit)
}

func TestDecodeUserAccessFlagsOff(t *testing.T) {
	access, err := decodeUserAccess([]byte{0x05, 0x81, 0x01, 0x0f})
	require.NoError(t, err)
	assert.Equal(t, uint8(0x02), access.EnableStatus)
	assert.False(t, access.CallbackOnly)
	assert.False(t, access.LinkAuthenticationEnabled)
	assert.False(t, access.IpmiMessagingEnabled)
	assert.Equal(t, "no-access", access.PrivilegeLimit)
}

func TestDecodeUserAccessShort(t *testing.T) {
	_, err := decodeUserAccess([]byte{0x0a, 0x43, 0x02})
	require.Error(t, err)
}

func TestDecodeUserEnableStatus(t *testing.T) {
	// 00b and 11b both mean the controller did not report the state. Folding
	// either into false would report an account as disabled that may well be
	// live, so both have to stay null.
	assert.Nil(t, decodeUserEnableStatus(0x0))
	assert.Nil(t, decodeUserEnableStatus(0x3))

	enabled := decodeUserEnableStatus(0x1)
	require.NotNil(t, enabled)
	assert.True(t, *enabled)

	disabled := decodeUserEnableStatus(0x2)
	require.NotNil(t, disabled)
	assert.False(t, *disabled)
}

func TestDecodeUserName(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "null padded to the full field width",
			data: append([]byte("admin"), make([]byte, 11)...),
			want: "admin",
		},
		{
			// Slot 1 is the null user. An empty name is a real state, not a
			// missing read, and is exactly what makes the slot anonymous.
			name: "empty name",
			data: make([]byte, 16),
			want: "",
		},
		{
			name: "short response from a controller that trims the padding",
			data: []byte("operator"),
			want: "operator",
		},
		{
			name: "space padded",
			data: append([]byte("root   "), make([]byte, 9)...),
			want: "root",
		},
		{
			// Nothing past the first null belongs to the name, even when a
			// controller leaves stale bytes in the tail of the field.
			name: "stops at the first null",
			data: []byte{'a', 'b', 0x00, 'x', 'y', 0x00},
			want: "ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeUserName(tt.data))
		})
	}
}
