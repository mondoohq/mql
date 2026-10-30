// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNtpServers_Full(t *testing.T) {
	cfg := `!
ntp server 0.pool.ntp.org prefer
ntp server 1.pool.ntp.org
ntp server 192.168.100.1 local-interface Management1
ntp server vrf MGMT 10.0.0.1 iburst key 3
ntp server 10.0.0.2 version 4 minpoll 4 maxpoll 10 source Loopback0
!
`
	servers := ParseNtpServers(cfg)
	require.Len(t, servers, 5)

	assert.Equal(t, "0.pool.ntp.org", servers[0].Address)
	assert.True(t, servers[0].Prefer)
	assert.Equal(t, 0, servers[0].KeyID)

	assert.Equal(t, "1.pool.ntp.org", servers[1].Address)
	assert.False(t, servers[1].Prefer)

	assert.Equal(t, "192.168.100.1", servers[2].Address)
	assert.Equal(t, "Management1", servers[2].LocalInterface)

	// The VRF qualifier precedes the address and must not be mistaken for it.
	assert.Equal(t, "10.0.0.1", servers[3].Address)
	assert.Equal(t, "MGMT", servers[3].VRF)
	assert.True(t, servers[3].IBurst)
	assert.Equal(t, 3, servers[3].KeyID)

	assert.Equal(t, "10.0.0.2", servers[4].Address)
	assert.Equal(t, 4, servers[4].Version)
	assert.Equal(t, 4, servers[4].MinPoll)
	assert.Equal(t, 10, servers[4].MaxPoll)
	// `source` is the alternate spelling of `local-interface`.
	assert.Equal(t, "Loopback0", servers[4].LocalInterface)
}

func TestParseNtpServers_None(t *testing.T) {
	assert.Empty(t, ParseNtpServers(""))
}

func TestParseNtpServers_IgnoresOtherNtpLines(t *testing.T) {
	// Only `ntp server` lines are sync sources; the authentication and serve
	// lines are parsed elsewhere and must not leak in as servers.
	cfg := `ntp authenticate
ntp authentication-key 1 sha256 7 secret
ntp trusted-key 1
ntp local-interface Management1
ntp serve all
ntp server 10.0.0.1
`
	servers := ParseNtpServers(cfg)
	require.Len(t, servers, 1)
	assert.Equal(t, "10.0.0.1", servers[0].Address)
}

func TestParseNtpServers_MalformedOptionKeepsServer(t *testing.T) {
	// An unparseable option value must not discard the server itself.
	cfg := `ntp server 10.0.0.1 key notanumber prefer
`
	servers := ParseNtpServers(cfg)
	require.Len(t, servers, 1)
	assert.Equal(t, "10.0.0.1", servers[0].Address)
	assert.Equal(t, 0, servers[0].KeyID)
	assert.True(t, servers[0].Prefer)
}

func TestParseNtpServeState_Disabled(t *testing.T) {
	state := ParseNtpServeState("ntp server 10.0.0.1\n")
	assert.False(t, state.Enabled)
	assert.Empty(t, state.AccessGroup)
}

func TestParseNtpServeState_ServeAll(t *testing.T) {
	state := ParseNtpServeState("ntp serve all\n")
	assert.True(t, state.Enabled)
	assert.Empty(t, state.AccessGroup)
}

func TestParseNtpServeState_AccessGroup(t *testing.T) {
	// Binding an access-group implies the device serves time, bounded to the
	// clients the list permits.
	state := ParseNtpServeState("ntp serve ipv4 access-group NTP-CLIENTS\n")
	assert.True(t, state.Enabled)
	assert.Equal(t, "NTP-CLIENTS", state.AccessGroup)
}

func TestParseNtpServeState_Negated(t *testing.T) {
	cfg := `ntp serve all
no ntp serve all
`
	state := ParseNtpServeState(cfg)
	assert.False(t, state.Enabled)
}
