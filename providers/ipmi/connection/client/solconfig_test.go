// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSOLEnable(t *testing.T) {
	on, err := decodeSOLEnable([]byte{0x01})
	require.NoError(t, err)
	require.NotNil(t, on)
	assert.True(t, *on)

	off, err := decodeSOLEnable([]byte{0x00})
	require.NoError(t, err)
	require.NotNil(t, off)
	assert.False(t, *off)

	_, err = decodeSOLEnable([]byte{})
	require.Error(t, err)
}

func TestDecodeSOLAuthentication(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want SOLAuthentication
	}{
		{
			// 0xc4: force encryption (bit 7), force authentication (bit 6),
			// administrator privilege.
			name: "encrypted and authenticated",
			data: []byte{0xc4},
			want: SOLAuthentication{ForceEncryption: true, ForceAuthentication: true, PrivilegeLevel: "administrator"},
		},
		{
			// 0x02 leaves both bits clear, so the host serial console is
			// carried in cleartext and reachable at user privilege.
			name: "cleartext console",
			data: []byte{0x02},
			want: SOLAuthentication{PrivilegeLevel: "user"},
		},
		{
			// Only encryption forced.
			name: "encrypted but unauthenticated",
			data: []byte{0x83},
			want: SOLAuthentication{ForceEncryption: true, PrivilegeLevel: "operator"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := decodeSOLAuthentication(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, *auth)
		})
	}

	_, err := decodeSOLAuthentication([]byte{})
	require.Error(t, err)
}

func TestDecodeSOLPayloadPort(t *testing.T) {
	port, err := decodeSOLPayloadPort([]byte{0x6f, 0x02})
	require.NoError(t, err)
	require.NotNil(t, port)
	assert.Equal(t, int64(623), *port)

	_, err = decodeSOLPayloadPort([]byte{0x6f})
	require.Error(t, err)
}
