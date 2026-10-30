// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func neighborByAddr(t *testing.T, cfg *BgpGlobalConfig, vrf, addr string) BgpNeighborConfig {
	t.Helper()
	for _, n := range cfg.Neighbors {
		if n.VRF == vrf && n.PeerAddress == addr {
			return n
		}
	}
	t.Fatalf("no neighbor %s in vrf %s; got %+v", addr, vrf, cfg.Neighbors)
	return BgpNeighborConfig{}
}

// TestParseBgpConfig_PeerGroupSettingsReachMembers is the case a leaf/spine
// fabric is actually built with: the session controls are configured once on
// the group and every session points at it. Reading only a session's own lines
// reports every member as unauthenticated with no route ceiling, so
// `peers.where(passwordConfigured == false)` flags the whole fabric.
func TestParseBgpConfig_PeerGroupSettingsReachMembers(t *testing.T) {
	cfg := ParseBgpConfig(`router bgp 65001
   neighbor SPINE peer group
   neighbor SPINE password 7 abcdef
   neighbor SPINE maximum-routes 12000
   neighbor SPINE ttl maximum-hops 2
   neighbor SPINE route-map IMPORT in
   neighbor 10.1.1.2 peer group SPINE
   neighbor 10.1.1.2 remote-as 65002
   neighbor 10.1.1.3 peer group SPINE
!
`)

	// The group definition is not itself a peer.
	for _, n := range cfg.Neighbors {
		assert.NotEqual(t, "SPINE", n.PeerAddress, "the group definition leaked into the neighbor list")
	}
	require.Len(t, cfg.Neighbors, 2)

	for _, addr := range []string{"10.1.1.2", "10.1.1.3"} {
		n := neighborByAddr(t, cfg, "default", addr)
		assert.True(t, n.PasswordConfigured, "%s: session is authenticated by its group", addr)
		assert.Equal(t, "7", n.PasswordEncryptionType, addr)
		assert.Equal(t, 12000, n.MaximumRoutes, addr)
		assert.Equal(t, 2, n.TtlMaximumHops, addr)
		assert.Equal(t, "IMPORT", n.InboundRouteMap, addr)
		assert.Equal(t, "SPINE", n.PeerGroup, addr)
	}
}

// TestParseBgpConfig_MemberSettingWinsOverGroup pins the precedence: a control
// written on the session itself is the one in effect.
func TestParseBgpConfig_MemberSettingWinsOverGroup(t *testing.T) {
	cfg := ParseBgpConfig(`router bgp 65001
   neighbor EDGE peer group
   neighbor EDGE maximum-routes 12000
   neighbor 10.1.1.2 peer group EDGE
   neighbor 10.1.1.2 maximum-routes 100
!
`)
	n := neighborByAddr(t, cfg, "default", "10.1.1.2")
	assert.Equal(t, 100, n.MaximumRoutes)
}

// TestParseBgpConfig_HyphenatedPeerGroupSpelling covers the `peer-group`
// rendering alongside `peer group`.
func TestParseBgpConfig_HyphenatedPeerGroupSpelling(t *testing.T) {
	cfg := ParseBgpConfig(`router bgp 65001
   neighbor SPINE peer-group
   neighbor SPINE password 7 abcdef
   neighbor 10.1.1.2 peer-group SPINE
!
`)
	require.Len(t, cfg.Neighbors, 1)
	n := neighborByAddr(t, cfg, "default", "10.1.1.2")
	assert.True(t, n.PasswordConfigured)
	assert.Equal(t, "SPINE", n.PeerGroup)
}

// TestParseBgpConfig_GroupsAreScopedToTheirVrf keeps a group in one routing
// instance from lending its settings to a same-named group in another.
func TestParseBgpConfig_GroupsAreScopedToTheirVrf(t *testing.T) {
	cfg := ParseBgpConfig(`router bgp 65001
   neighbor SHARED peer group
   neighbor SHARED password 7 abcdef
   vrf PROD
      neighbor SHARED peer group
      neighbor 10.100.1.2 peer group SHARED
!
`)
	n := neighborByAddr(t, cfg, "PROD", "10.100.1.2")
	assert.False(t, n.PasswordConfigured, "the default-instance group must not protect a PROD session")
}

// TestParseBgpConfig_StandaloneSessionIsUnchanged keeps the no-group path
// reporting exactly what the session's own lines say.
func TestParseBgpConfig_StandaloneSessionIsUnchanged(t *testing.T) {
	cfg := ParseBgpConfig(`router bgp 65001
   neighbor 10.1.1.2 remote-as 65002
   neighbor 10.1.1.2 password 0 plain
   neighbor 10.1.1.3 remote-as 65003
!
`)
	protected := neighborByAddr(t, cfg, "default", "10.1.1.2")
	assert.True(t, protected.PasswordConfigured)
	assert.Empty(t, protected.PeerGroup)

	bare := neighborByAddr(t, cfg, "default", "10.1.1.3")
	assert.False(t, bare.PasswordConfigured)
	assert.Zero(t, bare.MaximumRoutes)
}
