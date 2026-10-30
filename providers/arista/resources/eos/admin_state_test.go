// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseBlockAdminState_AbsentShutdownLineMeansRunning is the case that
// matters. Both blocks default to running and EOS omits defaults from the
// running-config, so a conventionally-configured device carries no shutdown
// line at all. Reading that absence as "shut down" reports a healthy device
// as down.
func TestParseBlockAdminState_AbsentShutdownLineMeansRunning(t *testing.T) {
	cfg := `mlag configuration
   domain-id mlag1
   local-interface Vlan4094
   peer-address 10.0.0.2
   peer-link Port-Channel1000
!
router bgp 65001
   router-id 10.0.0.1
   neighbor 10.1.1.2 remote-as 65002
!
`
	mlag := ParseBlockAdminState(cfg, "mlag configuration")
	assert.True(t, mlag.Configured)
	assert.False(t, mlag.Shutdown, "a peering with no shutdown line is up")

	bgp := ParseBlockAdminState(cfg, "router bgp ")
	assert.True(t, bgp.Configured)
	assert.False(t, bgp.Shutdown)
}

// TestParseBlockAdminState_RealDeviceCapture runs the assertion against the
// running-config captured from an actual vEOS switch, which is where the
// inverted default shows up in the repository itself.
func TestParseBlockAdminState_RealDeviceCapture(t *testing.T) {
	raw, err := os.ReadFile("testdata/mlag-config")
	require.NoError(t, err)

	got := ParseBlockAdminState(string(raw), "mlag configuration")
	assert.True(t, got.Configured)
	assert.False(t, got.Shutdown, "the captured device has a working MLAG peering")
}

func TestParseBlockAdminState_ExplicitShutdown(t *testing.T) {
	cfg := `mlag configuration
   domain-id mlag1
   shutdown
!
`
	got := ParseBlockAdminState(cfg, "mlag configuration")
	assert.True(t, got.Configured)
	assert.True(t, got.Shutdown)
}

// TestParseBlockAdminState_LastStatementWins covers a block that shuts down
// and is then brought back up, and the "default shutdown" spelling.
func TestParseBlockAdminState_LastStatementWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"no shutdown after shutdown", "   shutdown\n   no shutdown\n", false},
		{"shutdown after no shutdown", "   no shutdown\n   shutdown\n", true},
		{"default shutdown means running", "   default shutdown\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseBlockAdminState("mlag configuration\n"+tc.body+"!\n", "mlag configuration")
			assert.True(t, got.Configured)
			assert.Equal(t, tc.want, got.Shutdown)
		})
	}
}

// TestParseBlockAdminState_AbsentBlockIsNotConfigured keeps "not configured"
// distinct from "configured and running", which a single boolean would lose.
func TestParseBlockAdminState_AbsentBlockIsNotConfigured(t *testing.T) {
	got := ParseBlockAdminState("hostname leaf1\n!\n", "mlag configuration")
	assert.False(t, got.Configured)
	assert.False(t, got.Shutdown)
}

// TestParseBlockAdminState_HeaderIsNotAPrefixMatch stops "router bgp" from
// matching an unrelated block, while still matching any AS number.
func TestParseBlockAdminState_HeaderIsNotAPrefixMatch(t *testing.T) {
	assert.False(t, ParseBlockAdminState("mlag configuration extra\n   shutdown\n!\n", "mlag configuration").Configured)
	assert.True(t, ParseBlockAdminState("router bgp 4200000000\n   shutdown\n!\n", "router bgp ").Shutdown)
}
