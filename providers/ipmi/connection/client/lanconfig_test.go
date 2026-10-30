// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeLanAuthTypeEnables(t *testing.T) {
	// One byte per privilege level. Administrator is 0x01, which enables
	// authentication type none at administrator privilege: a session that
	// authenticates with nothing reaches the highest privilege.
	enables, err := decodeLanAuthTypeEnables([]byte{0x14, 0x14, 0x04, 0x01, 0x00})
	require.NoError(t, err)
	assert.Equal(t, []string{"md5", "password"}, enables["callback"])
	assert.Equal(t, []string{"md5", "password"}, enables["user"])
	assert.Equal(t, []string{"md5"}, enables["operator"])
	assert.Equal(t, []string{"none"}, enables["administrator"])
	assert.Equal(t, []string{}, enables["oem"])
}

func TestDecodeLanAuthTypeEnablesShort(t *testing.T) {
	_, err := decodeLanAuthTypeEnables([]byte{0x14, 0x14, 0x04, 0x01})
	require.Error(t, err)
}

func TestDecodeAuthTypeBits(t *testing.T) {
	// Bit 3 is reserved and must not become an authentication type.
	assert.Equal(t, []string{}, decodeAuthTypeBits(0x08))
	assert.Equal(t, []string{"none", "md2", "md5", "password", "oem"}, decodeAuthTypeBits(0x37))
}

func TestDecodeLanVlan(t *testing.T) {
	// VLAN 4094 (0xffe) with the enable bit set: low byte 0xfe, high nibble
	// 0x0f, enable bit 0x80.
	vlan, err := decodeLanVlan([]byte{0xfe, 0x8f})
	require.NoError(t, err)
	assert.True(t, vlan.Enabled)
	assert.Equal(t, int64(4094), vlan.ID)

	// A stored VLAN ID with the enable bit clear is configured but not in
	// use, which is a different answer from having no VLAN configured.
	off, err := decodeLanVlan([]byte{0x64, 0x00})
	require.NoError(t, err)
	assert.False(t, off.Enabled)
	assert.Equal(t, int64(100), off.ID)

	_, err = decodeLanVlan([]byte{0xfe})
	require.Error(t, err)
}

func TestDecodeLanBadPassword(t *testing.T) {
	// Threshold 5, attempt count reset interval 6 units and user lockout
	// interval 30 units. Both intervals are carried in tens of seconds, so
	// reporting the raw value would understate the lockout by a factor of 10.
	bad, err := decodeLanBadPassword([]byte{0x01, 0x05, 0x06, 0x00, 0x1e, 0x00})
	require.NoError(t, err)
	assert.True(t, bad.InvalidPasswordEventEnabled)
	assert.Equal(t, int64(5), bad.Threshold)
	assert.Equal(t, int64(60), bad.AttemptCountResetIntervalSeconds)
	assert.Equal(t, int64(300), bad.UserLockoutIntervalSeconds)
}

func TestDecodeLanBadPasswordDisabled(t *testing.T) {
	// A threshold of zero is the documented "no limit" value, so password
	// guessing on this channel is unbounded.
	bad, err := decodeLanBadPassword([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	assert.False(t, bad.InvalidPasswordEventEnabled)
	assert.Equal(t, int64(0), bad.Threshold)

	_, err = decodeLanBadPassword([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	require.Error(t, err)
}

func TestDecodeCipherSuiteCount(t *testing.T) {
	n, err := decodeCipherSuiteCount([]byte{0x0f})
	require.NoError(t, err)
	assert.Equal(t, 15, n)

	// The count field is five bits wide, so a controller can report a value
	// larger than the 16 entries the parameters carry. It has to be clamped
	// or it would index past the entry list.
	n, err = decodeCipherSuiteCount([]byte{0x1f})
	require.NoError(t, err)
	assert.Equal(t, 16, n)

	_, err = decodeCipherSuiteCount([]byte{})
	require.Error(t, err)
}

func TestDecodeCipherSuiteIDs(t *testing.T) {
	// First byte is the set selector; the entries follow.
	param := []byte{0x00, 0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	withCount, err := decodeCipherSuiteIDs(param, 9)
	require.NoError(t, err)
	assert.Equal(t, []int64{0, 1, 2, 3, 6, 7, 8, 11, 12}, withCount)

	// Without the count, a zero after the first entry is an unused slot
	// rather than a second appearance of cipher suite 0.
	withoutCount, err := decodeCipherSuiteIDs(param, -1)
	require.NoError(t, err)
	assert.Equal(t, []int64{0, 1, 2, 3, 6, 7, 8, 11, 12}, withoutCount)

	_, err = decodeCipherSuiteIDs([]byte{0x00}, -1)
	require.Error(t, err)
}

func TestDecodeCipherSuitePrivileges(t *testing.T) {
	// A reserved byte followed by two four-bit levels per byte, low nibble
	// first. 0x40 is entry 0 unused and entry 1 at administrator, which is
	// the shape that decides cipherZeroEnabled.
	param := []byte{0x00, 0x40, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	privs, err := decodeCipherSuitePrivileges(param)
	require.NoError(t, err)
	assert.Equal(t, uint8(0x00), privs[0])
	assert.Equal(t, uint8(0x04), privs[1])
	assert.Equal(t, uint8(0x04), privs[2])
	assert.Equal(t, uint8(0x04), privs[3])

	_, err = decodeCipherSuitePrivileges(make([]byte, 8))
	require.Error(t, err)
}

func TestCipherSuiteLevels(t *testing.T) {
	tests := []struct {
		name           string
		ids            []int64
		privs          [maxCipherSuiteEntries]uint8
		wantLevels     map[string]string
		wantCipherZero bool
	}{
		{
			// Cipher suite 0 present and left at administrator: any password
			// is accepted for a full administrative session.
			name:           "cipher zero at administrator",
			ids:            []int64{0, 3},
			privs:          [maxCipherSuiteEntries]uint8{0x04, 0x04},
			wantLevels:     map[string]string{"0": "administrator", "3": "administrator"},
			wantCipherZero: true,
		},
		{
			// Cipher suite 0 offered but marked unused, which is how it is
			// switched off. Reporting the entry alone would be a false alarm.
			name:           "cipher zero present but unused",
			ids:            []int64{0, 3},
			privs:          [maxCipherSuiteEntries]uint8{0x00, 0x04},
			wantLevels:     map[string]string{"0": "unspecified", "3": "administrator"},
			wantCipherZero: false,
		},
		{
			// Cipher suite 0 not offered at all.
			name:           "cipher zero absent",
			ids:            []int64{3, 8},
			privs:          [maxCipherSuiteEntries]uint8{0x04, 0x04},
			wantLevels:     map[string]string{"3": "administrator", "8": "administrator"},
			wantCipherZero: false,
		},
		{
			// Even the lowest privilege still means suite 0 opens a session.
			name:           "cipher zero at callback",
			ids:            []int64{0},
			privs:          [maxCipherSuiteEntries]uint8{0x01},
			wantLevels:     map[string]string{"0": "callback"},
			wantCipherZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			levels, cipherZero := cipherSuiteLevels(tt.ids, tt.privs)
			assert.Equal(t, tt.wantLevels, levels)
			assert.Equal(t, tt.wantCipherZero, cipherZero)
		})
	}
}
