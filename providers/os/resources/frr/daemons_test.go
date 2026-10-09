// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func areaFor(areas []OSPFArea, id string) *OSPFArea {
	for i := range areas {
		if areas[i].ID == id {
			return &areas[i]
		}
	}
	return nil
}

func bfdFor(peers []BFDPeer, name string) *BFDPeer {
	for i := range peers {
		if peers[i].Name == name {
			return &peers[i]
		}
	}
	return nil
}

func interfaceFor(ifaces []Interface, name string) *Interface {
	for i := range ifaces {
		if ifaces[i].Name == name {
			return &ifaces[i]
		}
	}
	return nil
}

func TestOSPFInstances(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	instances := cfg.OSPFInstances()
	require.Len(t, instances, 2)

	v2 := instances[0]
	assert.Equal(t, int64(2), v2.Version)
	assert.Equal(t, "", v2.VRF)
	assert.Equal(t, "192.0.2.30", v2.RouterID)
	assert.True(t, v2.LogAdjacencyChanges)
	assert.True(t, v2.DefaultInformationOriginate)
	assert.Equal(t, "on-startup 300", v2.MaxMetricRouterLsa)
	assert.Equal(t, []string{"connected", "static route-map rm_export_local"}, v2.Redistribute)

	// A passive default with one exemption is the safe shape, and both sides
	// have to be readable to check it.
	assert.True(t, v2.PassiveInterfaceDefault)
	assert.Equal(t, []string{"swp1"}, v2.NoPassiveInterfaces)
	assert.Empty(t, v2.PassiveInterfaces)

	require.Len(t, v2.Networks, 2)
	assert.Equal(t, "192.0.2.30/32", v2.Networks[0].Prefix)
	assert.Equal(t, "0.0.0.0", v2.Networks[0].Area)

	// The backbone is authenticated, which is the finding a policy checks.
	backbone := areaFor(v2.Areas, "0.0.0.0")
	require.NotNil(t, backbone)
	assert.Equal(t, "message-digest", backbone.Authentication)

	stub := areaFor(v2.Areas, "0.0.0.1")
	require.NotNil(t, stub)
	assert.Equal(t, "stub", stub.Type)
	assert.True(t, stub.NoSummary)
	assert.Equal(t, []string{"10.10.0.0/16"}, stub.Ranges)
	assert.Equal(t, "", stub.Authentication)

	nssa := areaFor(v2.Areas, "0.0.0.2")
	require.NotNil(t, nssa)
	assert.Equal(t, "nssa", nssa.Type)
	assert.Equal(t, []string{"prefix pl_export_base in"}, nssa.FilterLists)

	virtual := areaFor(v2.Areas, "0.0.0.3")
	require.NotNil(t, virtual)
	assert.Equal(t, []string{"192.0.2.31"}, virtual.VirtualLinks)

	v3 := instances[1]
	assert.Equal(t, int64(3), v3.Version)
	assert.Equal(t, "cluster", v3.VRF)
	assert.Equal(t, "192.0.2.30", v3.RouterID)
}

func TestISISInstances(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	instances := cfg.ISISInstances()
	require.Len(t, instances, 1)

	s := instances[0]
	assert.Equal(t, "FABRIC", s.Tag)
	assert.Equal(t, "49.0001.1920.0200.0030.00", s.Net)
	assert.Equal(t, "level-2-only", s.IsType)
	assert.Equal(t, "wide", s.MetricStyle)
	assert.True(t, s.LogAdjacencyChanges)
	// The password itself stays out of the resource, only its presence and
	// how it is sent are reported.
	assert.True(t, s.AreaPasswordSet)
	assert.Equal(t, "md5", s.AreaPasswordMode)
	assert.True(t, s.DomainPasswordSet)
	assert.Equal(t, "clear", s.DomainPasswordMode)
	assert.Equal(t, []string{"ipv4 connected level-2"}, s.Redistribute)
}

func TestBFDPeers(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	peers := cfg.BFDPeers()
	require.Len(t, peers, 3)

	profile := bfdFor(peers, "fabric")
	require.NotNil(t, profile)
	assert.Equal(t, "profile", profile.Kind)
	assert.Equal(t, int64(3), profile.DetectMultiplier)
	assert.Equal(t, int64(150), profile.TransmitInterval)
	assert.Equal(t, int64(150), profile.ReceiveInterval)
	assert.True(t, profile.EchoMode)
	assert.Equal(t, int64(50), profile.EchoInterval)

	single := bfdFor(peers, "192.0.2.31")
	require.NotNil(t, single)
	assert.Equal(t, "peer", single.Kind)
	assert.Equal(t, "swp1", single.Interface)
	assert.Equal(t, int64(254), single.MinimumTTL)
	assert.False(t, single.MultiHop)

	multi := bfdFor(peers, "203.0.113.9")
	require.NotNil(t, multi)
	assert.True(t, multi.MultiHop)
	assert.Equal(t, "192.0.2.30", multi.LocalAddress)
	assert.Equal(t, "cluster", multi.VRF)
	assert.Equal(t, "fabric", multi.Profile)
	assert.True(t, multi.PassiveMode)
	assert.True(t, multi.Shutdown)
	// An unset timer stays -1, so it is not read as an aggressive zero.
	assert.Equal(t, int64(-1), multi.DetectMultiplier)
}

func TestPBRMaps(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	maps := cfg.PBRMaps()
	require.Len(t, maps, 1)
	require.Len(t, maps[0].Rules, 2)
	assert.Equal(t, "hbn", maps[0].Name)

	// A rule that sends traffic to another VRF moves it across a tenant
	// boundary without a route.
	first := maps[0].Rules[0]
	assert.Equal(t, int64(1), first.Sequence)
	assert.Equal(t, "10.100.0.0/16", first.SourcePrefix)
	assert.Equal(t, "443", first.DestPort)
	assert.Equal(t, "tcp", first.Protocol)
	assert.Equal(t, "vr.mgmt", first.Nexthop)
	assert.Equal(t, "vr.mgmt", first.NexthopVRF)

	second := maps[0].Rules[1]
	assert.Equal(t, int64(2), second.Sequence)
	assert.Equal(t, "10.200.0.0/16", second.DestPrefix)
	assert.Equal(t, int64(1005), second.Table)
}

func TestSegmentRouting(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	sr, ok := cfg.SegmentRoutingBlock()
	require.True(t, ok)
	assert.True(t, sr.MPLSEnabled)
	require.Len(t, sr.SRv6Locators, 1)
	assert.Equal(t, "MAIN", sr.SRv6Locators[0].Name)
	assert.Equal(t, "2001:db8:aaaa::/48", sr.SRv6Locators[0].Prefix)

	// A configuration without the block reports none rather than an empty one.
	other := parseFixture(t, "frr-bgp.conf")
	_, ok = other.SegmentRoutingBlock()
	assert.False(t, ok)
}

// TestInterfaceProtocols covers the link settings of the interior gateway
// protocols. An interface without authentication accepts an adjacency from
// anything on the link.
func TestInterfaceProtocols(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	ifaces := cfg.Interfaces()
	require.Len(t, ifaces, 3)

	swp1 := interfaceFor(ifaces, "swp1")
	require.NotNil(t, swp1)
	p := swp1.Protocols
	assert.Equal(t, "0.0.0.0", p.OSPFArea)
	assert.Equal(t, "message-digest", p.OSPFAuthentication)
	assert.True(t, p.OSPFMessageDigestKeySet)
	assert.Equal(t, "point-to-point", p.OSPFNetworkType)
	assert.Equal(t, int64(3), p.OSPFHelloInterval)
	assert.Equal(t, int64(9), p.OSPFDeadInterval)
	assert.Equal(t, int64(100), p.OSPFCost)
	assert.Equal(t, int64(0), p.OSPFPriority)
	assert.True(t, p.BFDEnabled)
	assert.False(t, p.OSPFPassive)

	swp2 := interfaceFor(ifaces, "swp2")
	require.NotNil(t, swp2)
	p = swp2.Protocols
	assert.Equal(t, "FABRIC", p.ISISTag)
	assert.Equal(t, "level-2-only", p.ISISCircuitType)
	assert.Equal(t, "point-to-point", p.ISISNetworkType)
	assert.True(t, p.ISISPasswordSet)
	assert.Equal(t, "md5 keychain-1", p.ISISAuthenticationMode)
	assert.True(t, p.PIMEnabled)
	assert.True(t, p.IGMPEnabled)
	// An unset OSPF timer stays -1 on an interface that runs IS-IS.
	assert.Equal(t, int64(-1), p.OSPFCost)

	lo := interfaceFor(ifaces, "lo")
	require.NotNil(t, lo)
	assert.True(t, lo.Protocols.OSPFPassive)
	assert.Equal(t, "", lo.Protocols.OSPFAuthentication)
}

// TestServiceSettings covers the daemon-wide settings, which decide who
// reaches the shell and what the router records.
func TestServiceSettings(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	s := cfg.ServiceSettings()

	require.Len(t, s.LogTargets, 3)
	assert.Equal(t, "file", s.LogTargets[0].Target)
	assert.Equal(t, "/var/log/frr/frr.log", s.LogTargets[0].Destination)
	assert.Equal(t, "informational", s.LogTargets[0].Level)
	assert.Equal(t, "syslog", s.LogTargets[1].Target)
	assert.Equal(t, "warnings", s.LogTargets[1].Level)
	assert.Equal(t, "stdout", s.LogTargets[2].Target)

	assert.True(t, s.LogCommands)
	assert.True(t, s.PasswordSet)
	assert.True(t, s.EnablePasswordSet)
	assert.True(t, s.AgentxEnabled)
	assert.True(t, s.IntegratedVtyshConfig)
	assert.True(t, s.AdvancedVty)

	require.Len(t, s.Users, 2)
	assert.Equal(t, "admin", s.Users[0].Name)
	assert.True(t, s.Users[0].NoPassword)
	assert.Equal(t, int64(15), s.Users[1].Privilege)

	// A configuration without these lines reports them as absent.
	plain := parseFixture(t, "frr-bgp.conf")
	ps := plain.ServiceSettings()
	assert.False(t, ps.PasswordSet)
	assert.False(t, ps.AgentxEnabled)
	assert.False(t, ps.AdvancedVty)
	assert.True(t, ps.IntegratedVtyshConfig)
	assert.Len(t, ps.LogTargets, 2)
}

// TestParse_SegmentRoutingNesting pins the nesting of the segment routing
// tree, which is several levels deep and terminated only by `exit`.
func TestParse_SegmentRoutingNesting(t *testing.T) {
	cfg := parseFixture(t, "frr-daemons.conf")
	sr := findBlock(cfg, "segment-routing", "")
	require.NotNil(t, sr)
	require.Len(t, sr.Blocks, 1)
	assert.Equal(t, "srv6", sr.Blocks[0].Type)
	require.Len(t, sr.Blocks[0].Blocks, 1)
	assert.Equal(t, "locators", sr.Blocks[0].Blocks[0].Type)
	require.Len(t, sr.Blocks[0].Blocks[0].Blocks, 1)
	assert.Equal(t, "locator", sr.Blocks[0].Blocks[0].Blocks[0].Type)

	// The block after it is still a top-level block.
	assert.Nil(t, findBlock(cfg, "locator", "MAIN"))
}
