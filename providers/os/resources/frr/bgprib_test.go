// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func evpnRouteFor(routes []EVPNRoute, prefix string) *EVPNRoute {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}

func TestStreamEVPNRoutes(t *testing.T) {
	set, err := StreamEVPNRoutes(bytes.NewReader(readFixture(t, "show_bgp_l2vpn_evpn.json")), 0)
	require.NoError(t, err)

	assert.Equal(t, int64(3), set.Total)
	assert.False(t, set.Truncated)
	require.Len(t, set.Routes, 3)

	// A type 2 route carries the MAC of a tenant workload.
	mac := evpnRouteFor(set.Routes, "[2]:[0]:[48]:[aa:bb:cc:00:10:01]")
	require.NotNil(t, mac)
	assert.Equal(t, "192.0.2.30:2", mac.RD)
	assert.Equal(t, int64(2), mac.RouteType)
	assert.Equal(t, "mac-ip", mac.RouteTypeName)
	assert.Equal(t, "aa:bb:cc:00:10:01", mac.MACAddress)
	assert.Equal(t, "", mac.IP)
	assert.Equal(t, []string{"65100:4001"}, mac.RouteTargets)
	require.Len(t, mac.Paths, 1)
	assert.True(t, mac.Paths[0].BestPath)
	assert.Equal(t, "192.0.2.30", mac.Paths[0].Nexthop)
	assert.Equal(t, int64(32768), mac.Paths[0].Weight)

	// A type 2 route with an IP carries both, and a remote path names its peer.
	macip := evpnRouteFor(set.Routes, "[2]:[0]:[48]:[aa:bb:cc:00:10:02]:[32]:[10.10.0.5]")
	require.NotNil(t, macip)
	assert.Equal(t, "aa:bb:cc:00:10:02", macip.MACAddress)
	assert.Equal(t, "10.10.0.5", macip.IP)
	require.Len(t, macip.Paths, 1)
	p := macip.Paths[0]
	assert.Equal(t, "192.0.2.31", p.Peer)
	assert.Equal(t, "65000 65101", p.ASPath)
	assert.Equal(t, "IGP", p.Origin)
	assert.Equal(t, int64(100), p.LocalPreference)
	assert.Equal(t, []string{"65100:200"}, p.Communities)
	assert.Equal(t, []string{"65100:1:2"}, p.LargeCommunities)
	assert.Equal(t, []string{"RT:65100:4001", "RT:65100:5000", "ET:8", "MM:0"}, p.ExtendedCommunities)
	// Two route targets on one path is how a route reaches two VRFs.
	assert.Equal(t, []string{"65100:4001", "65100:5000"}, p.RouteTargets)

	// A type 5 route carries the tenant prefix with its length.
	ipPrefix := evpnRouteFor(set.Routes, "[5]:[0]:[24]:[10.20.0.0]")
	require.NotNil(t, ipPrefix)
	assert.Equal(t, int64(5), ipPrefix.RouteType)
	assert.Equal(t, "ip-prefix", ipPrefix.RouteTypeName)
	assert.Equal(t, "10.20.0.0/24", ipPrefix.IP)
	assert.Equal(t, []string{"65100:5010"}, ipPrefix.RouteTargets)
}

// TestStreamEVPNRoutes_PerVNIShape covers `show bgp l2vpn evpn route vni <id>
// json`, which prints the prefixes at the top level instead of under a route
// distinguisher.
func TestStreamEVPNRoutes_PerVNIShape(t *testing.T) {
	set, err := StreamEVPNRoutes(bytes.NewReader(readFixture(t, "show_bgp_l2vpn_evpn_vni.json")), 0)
	require.NoError(t, err)

	assert.Equal(t, int64(1), set.Total)
	require.Len(t, set.Routes, 1)
	assert.Equal(t, "", set.Routes[0].RD)
	assert.Equal(t, int64(3), set.Routes[0].RouteType)
	assert.Equal(t, "inclusive-multicast", set.Routes[0].RouteTypeName)
	assert.Equal(t, "192.0.2.31", set.Routes[0].IP)
}

// TestStreamEVPNRoutes_Bounded pins the bound of the EVPN table, which holds
// one entry per MAC and per prefix of every tenant.
func TestStreamEVPNRoutes_Bounded(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"192.0.2.30:2":{"rd":"192.0.2.30:2"`)
	const prefixes = 300
	for i := 0; i < prefixes; i++ {
		fmt.Fprintf(&buf, `,"[2]:[0]:[48]:[aa:bb:cc:00:%02x:%02x]":{"prefix":"[2]:[0]:[48]:[aa:bb:cc:00:%02x:%02x]",`+
			`"paths":[{"valid":true,"nexthops":[{"ip":"192.0.2.30"}],"extendedCommunity":{"string":"RT:65100:4001"}}]}`,
			i/256, i%256, i/256, i%256)
	}
	buf.WriteString(`,"numPrefix":300,"numPaths":300}}`)

	set, err := StreamEVPNRoutes(bytes.NewReader(buf.Bytes()), 25)
	require.NoError(t, err)
	assert.Len(t, set.Routes, 25)
	assert.True(t, set.Truncated)
	assert.Equal(t, int64(prefixes), set.Total)
}

func TestStreamEVPNRoutes_EmptyAndBroken(t *testing.T) {
	set, err := StreamEVPNRoutes(strings.NewReader("{}"), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), set.Total)

	set, err = StreamEVPNRoutes(strings.NewReader(""), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), set.Total)

	_, err = StreamEVPNRoutes(strings.NewReader(`["nope"]`), 0)
	require.Error(t, err)
}

func TestStreamPeerRoutes(t *testing.T) {
	set, err := StreamPeerRoutes(bytes.NewReader(readFixture(t, "show_bgp_neighbor_advertised.json")), 0)
	require.NoError(t, err)

	assert.Equal(t, int64(2), set.Total)
	assert.False(t, set.Truncated)
	// The command reports what its policy dropped, which is the count a
	// policy compares against the session counters.
	assert.Equal(t, int64(1), set.FilteredCount)
	require.Len(t, set.Routes, 2)

	var local, learned *BGPRoute
	for i := range set.Routes {
		switch set.Routes[i].Prefix {
		case "192.0.2.30/32":
			local = &set.Routes[i]
		case "10.100.0.0/16":
			learned = &set.Routes[i]
		}
	}
	require.NotNil(t, local)
	assert.Equal(t, int64(32), local.PrefixLen)
	assert.True(t, local.BestPath)
	assert.Equal(t, "0.0.0.0", local.Nexthop)
	assert.Equal(t, []string{"65100:200"}, local.Communities)

	require.NotNil(t, learned)
	assert.Equal(t, "65000", learned.ASPath)
	assert.Equal(t, "Incomplete", learned.Origin)
	assert.Equal(t, "192.0.2.1", learned.Nexthop)
	assert.Equal(t, []string{"65100:5000"}, learned.RouteTargets)
}

func TestStreamPeerRoutes_Bounded(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"bgpTableVersion":1,"routes":{`)
	const prefixes = 200
	for i := 0; i < prefixes; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, `"10.%d.%d.0/24":[{"network":"10.%d.%d.0/24","prefixLen":24,"valid":true,`+
			`"nexthops":[{"ip":"192.0.2.1"}]}]`, i/256, i%256, i/256, i%256)
	}
	fmt.Fprintf(&buf, `},"totalPrefixCounter":%d,"filteredPrefixCounter":0}`, prefixes)

	set, err := StreamPeerRoutes(bytes.NewReader(buf.Bytes()), 15)
	require.NoError(t, err)
	assert.Len(t, set.Routes, 15)
	assert.True(t, set.Truncated)
	assert.Equal(t, int64(prefixes), set.Total)
	assert.Equal(t, int64(0), set.FilteredCount)
}

// TestStreamPeerRoutes_SinglePathObject covers the versions that print one
// path object per prefix instead of a list.
func TestStreamPeerRoutes_SinglePathObject(t *testing.T) {
	src := `{"routes":{"10.0.0.0/8":{"network":"10.0.0.0/8","valid":true,"path":"65000",
		"nexthops":[{"ip":"192.0.2.1"}],"community":"65100:1 65100:2"}}}`
	set, err := StreamPeerRoutes(strings.NewReader(src), 0)
	require.NoError(t, err)
	require.Len(t, set.Routes, 1)
	assert.Equal(t, "10.0.0.0/8", set.Routes[0].Prefix)
	assert.Equal(t, []string{"65100:1", "65100:2"}, set.Routes[0].Communities)
	// A command without the counter leaves it unknown rather than zero.
	assert.Equal(t, int64(-1), set.FilteredCount)
}

func TestStreamPeerRoutes_EmptyAndBroken(t *testing.T) {
	set, err := StreamPeerRoutes(strings.NewReader(`{"routes":{}}`), 0)
	require.NoError(t, err)
	assert.Empty(t, set.Routes)
	assert.Equal(t, int64(0), set.Total)

	set, err = StreamPeerRoutes(strings.NewReader(""), 0)
	require.NoError(t, err)
	assert.Empty(t, set.Routes)

	_, err = StreamPeerRoutes(strings.NewReader(`"nope"`), 0)
	require.Error(t, err)
}

// TestPeerRoutesRefused covers the answer FRR gives for received routes when
// the session has no inbound soft reconfiguration. It exits zero, so the
// text is the only signal.
func TestPeerRoutesRefused(t *testing.T) {
	assert.True(t, Refused(readFixture(t, "show_bgp_neighbor_received_refused.txt")))
}

func TestEVPNRouteTypeName(t *testing.T) {
	assert.Equal(t, "ethernet-auto-discovery", evpnRouteTypeName(1))
	assert.Equal(t, "mac-ip", evpnRouteTypeName(2))
	assert.Equal(t, "inclusive-multicast", evpnRouteTypeName(3))
	assert.Equal(t, "ethernet-segment", evpnRouteTypeName(4))
	assert.Equal(t, "ip-prefix", evpnRouteTypeName(5))
	assert.Equal(t, "", evpnRouteTypeName(9))
}

func TestRouteTargetOf(t *testing.T) {
	rt, ok := routeTargetOf("RT:65100:5000")
	assert.True(t, ok)
	assert.Equal(t, "65100:5000", rt)

	_, ok = routeTargetOf("ET:8")
	assert.False(t, ok)
}

// TestStreamEVPNRoutes_RDAfterPrefixes covers a section that prints its route
// distinguisher after its prefixes. The prefixes still carry the right value.
func TestStreamEVPNRoutes_RDAfterPrefixes(t *testing.T) {
	src := `{"192.0.2.30:7":{
		"[2]:[0]:[48]:[aa:bb:cc:00:20:01]":{"prefix":"[2]:[0]:[48]:[aa:bb:cc:00:20:01]",
			"paths":[{"valid":true,"nexthops":[{"ip":"192.0.2.30"}]}]},
		"rd":"192.0.2.30:7","numPrefix":1}}`
	set, err := StreamEVPNRoutes(strings.NewReader(src), 0)
	require.NoError(t, err)
	require.Len(t, set.Routes, 1)
	assert.Equal(t, "192.0.2.30:7", set.Routes[0].RD)
}

// TestStreamEVPNRoutes_ScalarSection covers a top-level counter this code
// does not know, which must not stop the walk.
func TestStreamEVPNRoutes_ScalarSection(t *testing.T) {
	src := `{"unknownCounter":7,"unknownList":[1,2,3],"192.0.2.30:2":{"rd":"192.0.2.30:2",
		"[3]:[0]:[32]:[192.0.2.31]":{"prefix":"[3]:[0]:[32]:[192.0.2.31]","paths":[]}}}`
	set, err := StreamEVPNRoutes(strings.NewReader(src), 0)
	require.NoError(t, err)
	require.Len(t, set.Routes, 1)
	assert.Equal(t, int64(3), set.Routes[0].RouteType)
}

// TestStreamEVPNRoutes_BrokenEntryStopsCleanly covers a prefix whose value
// cannot be decoded. The walk must not carry on from the middle of a
// section, because everything after that point would be read as noise.
func TestStreamEVPNRoutes_BrokenEntryStopsCleanly(t *testing.T) {
	src := `{"192.0.2.30:2":{"rd":"192.0.2.30:2",` +
		`"[2]:[0]:[48]:[aa:bb:cc:00:10:01]":{"prefix":"[2]:[0]:[48]:[aa:bb:cc:00:10:01]","paths":[]},` +
		`"[2]:[0]:[48]:[aa:bb:cc:00:10:02]":"not an object",` +
		`"[2]:[0]:[48]:[aa:bb:cc:00:10:03]":{"prefix":"[2]:[0]:[48]:[aa:bb:cc:00:10:03]","paths":[]}}}`
	set, err := StreamEVPNRoutes(strings.NewReader(src), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(3), set.Total)
	require.Len(t, set.Routes, 2)
	assert.Equal(t, "[2]:[0]:[48]:[aa:bb:cc:00:10:01]", set.Routes[0].Prefix)
	assert.Equal(t, "[2]:[0]:[48]:[aa:bb:cc:00:10:03]", set.Routes[1].Prefix)

	// A truncated document is an error rather than a partial answer.
	_, err = StreamEVPNRoutes(strings.NewReader(`{"192.0.2.30:2":{"rd":`), 0)
	require.Error(t, err)
}

// TestStreamPeerRoutes_LimitWithManyPaths pins that a prefix with several
// paths cannot push the result past the limit.
func TestStreamPeerRoutes_LimitWithManyPaths(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"routes":{`)
	for i := 0; i < 10; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, `"10.0.%d.0/24":[`, i)
		for j := 0; j < 5; j++ {
			if j > 0 {
				buf.WriteString(",")
			}
			fmt.Fprintf(&buf, `{"network":"10.0.%d.0/24","valid":true,"nexthops":[{"ip":"192.0.2.%d"}]}`, i, j+1)
		}
		buf.WriteString("]")
	}
	buf.WriteString(`},"totalPrefixCounter":10}`)

	set, err := StreamPeerRoutes(bytes.NewReader(buf.Bytes()), 7)
	require.NoError(t, err)
	assert.Len(t, set.Routes, 7)
	assert.True(t, set.Truncated)
	assert.Equal(t, int64(10), set.Total)
}

// TestFillEVPNPrefixParts_ExtraFields pins that the prefix length of a type
// 5 route is read next to the IP, so a version that appends further fields
// does not move it.
func TestFillEVPNPrefixParts_ExtraFields(t *testing.T) {
	route := EVPNRoute{Prefix: "[5]:[0]:[24]:[10.20.0.0]:[extra]"}
	fillEVPNPrefixParts(&route)
	assert.Equal(t, int64(5), route.RouteType)
	assert.Equal(t, "10.20.0.0/24", route.IP)
}

// TestRIBTruncatedOnDroppedEntries pins that a RIB result which does not
// hold everything the command reported says so, whichever reason applies.
func TestRIBTruncatedOnDroppedEntries(t *testing.T) {
	// An EVPN prefix that cannot be read is missing data.
	evpn := `{"192.0.2.30:2":{"rd":"192.0.2.30:2",` +
		`"[2]:[0]:[48]:[aa:bb:cc:00:10:01]":{"prefix":"[2]:[0]:[48]:[aa:bb:cc:00:10:01]","paths":[]},` +
		`"[2]:[0]:[48]:[aa:bb:cc:00:10:02]":"nope"}}`
	set, err := StreamEVPNRoutes(strings.NewReader(evpn), 0)
	require.NoError(t, err)
	assert.Len(t, set.Routes, 1)
	assert.Equal(t, int64(2), set.Total)
	assert.True(t, set.Truncated)

	// A peer route whose paths cannot be read is missing data too.
	peer := `{"routes":{"10.0.0.0/8":[{"network":"10.0.0.0/8"}],"10.1.0.0/16":"nope"}}`
	routes, err := StreamPeerRoutes(strings.NewReader(peer), 0)
	require.NoError(t, err)
	assert.Len(t, routes.Routes, 1)
	assert.True(t, routes.Truncated)

	// A complete answer still reports false.
	whole := `{"routes":{"10.0.0.0/8":[{"network":"10.0.0.0/8"}]}}`
	routes, err = StreamPeerRoutes(strings.NewReader(whole), 0)
	require.NoError(t, err)
	assert.False(t, routes.Truncated)
}
