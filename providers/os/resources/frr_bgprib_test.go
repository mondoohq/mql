// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestInitFrrEvpnRouteTable(t *testing.T) {
	args, _, err := initFrrEvpnRouteTable(nil, map[string]*llx.RawData{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), args["vni"].Value)
	assert.Equal(t, int64(5000), args["limit"].Value)
	assert.Equal(t, "frr.evpn.routeTable/all", args["__id"].Value)

	args, _, err = initFrrEvpnRouteTable(nil, map[string]*llx.RawData{
		"vni":   llx.IntData(4001),
		"limit": llx.IntData(50),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(4001), args["vni"].Value)
	assert.Equal(t, "frr.evpn.routeTable/vni/4001", args["__id"].Value)

	for _, bad := range []map[string]*llx.RawData{
		{"vni": llx.IntData(-1)},
		{"vni": llx.IntData(16777216)},
		{"vni": llx.StringData("4001")},
		{"limit": llx.IntData(0)},
	} {
		_, _, err := initFrrEvpnRouteTable(nil, bad)
		require.Error(t, err)
	}
}

func TestInitFrrBgpPeerRoutes(t *testing.T) {
	args, _, err := initFrrBgpPeerRoutes(nil, map[string]*llx.RawData{
		"peer": llx.StringData("swp1"),
	})
	require.NoError(t, err)
	assert.Equal(t, "advertised", args["direction"].Value)
	assert.Equal(t, "ipv4", args["afi"].Value)
	assert.Equal(t, "", args["vrf"].Value)
	assert.Equal(t, int64(5000), args["limit"].Value)
	assert.Equal(t, "frr.bgp.peerRoutes/default/ipv4/advertised/swp1", args["__id"].Value)

	args, _, err = initFrrBgpPeerRoutes(nil, map[string]*llx.RawData{
		"peer":      llx.StringData("2001:db8::1"),
		"direction": llx.StringData("Received"),
		"vrf":       llx.StringData("t-blue"),
		"afi":       llx.StringData("IPv6"),
	})
	require.NoError(t, err)
	assert.Equal(t, "received", args["direction"].Value)
	assert.Equal(t, "ipv6", args["afi"].Value)
	assert.Equal(t, "frr.bgp.peerRoutes/t-blue/ipv6/received/2001:db8::1", args["__id"].Value)
}

// TestInitFrrBgpPeerRoutes_Rejects covers the arguments that reach the vtysh
// command line.
func TestInitFrrBgpPeerRoutes_Rejects(t *testing.T) {
	tests := []struct {
		name string
		args map[string]*llx.RawData
	}{
		{"missing peer", map[string]*llx.RawData{}},
		{"wrong peer type", map[string]*llx.RawData{"peer": llx.IntData(1)}},
		{"command injection", map[string]*llx.RawData{"peer": llx.StringData(`x"; reboot; "`)}},
		{"shell substitution in vrf", map[string]*llx.RawData{
			"peer": llx.StringData("swp1"), "vrf": llx.StringData("$(id)"),
		}},
		{"space in peer", map[string]*llx.RawData{"peer": llx.StringData("swp1 swp2")}},
		{"unknown direction", map[string]*llx.RawData{
			"peer": llx.StringData("swp1"), "direction": llx.StringData("both"),
		}},
		{"unknown address family", map[string]*llx.RawData{
			"peer": llx.StringData("swp1"), "afi": llx.StringData("ipv5"),
		}},
		{"zero limit", map[string]*llx.RawData{
			"peer": llx.StringData("swp1"), "limit": llx.IntData(0),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := initFrrBgpPeerRoutes(nil, tc.args)
			require.Error(t, err)
		})
	}
}

func TestFrrRIBIDs(t *testing.T) {
	assert.Equal(t, "frr.evpn.routeTable/all", frrEVPNRouteTableID(0))
	assert.Equal(t, "frr.evpn.routeTable/vni/100", frrEVPNRouteTableID(100))
	assert.Equal(t, "frr.bgp.peerRoutes/default/ipv4/advertised/swp1",
		frrPeerRoutesID("swp1", "advertised", "", "ipv4"))
	assert.Equal(t, "frr.bgp.peerRoutes/cluster/l2vpn/received/192.0.2.1",
		frrPeerRoutesID("192.0.2.1", "received", "cluster", "l2vpn"))
}

// TestFrrBgpPeerRoutesLoadValidates pins that the values which reach the
// vtysh command line are checked again when the resource is built from a
// recording rather than from init.
func TestFrrBgpPeerRoutesLoadValidates(t *testing.T) {
	// The direction and the address family are part of the command, so a
	// value that init would have rejected must not slip through later.
	for _, tc := range []struct {
		name      string
		direction string
		afi       string
	}{
		{"tampered direction", `x"; reboot; "`, "ipv4"},
		{"tampered address family", "advertised", `x"; reboot; "`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &mqlFrrBgpPeerRoutes{}
			res.Peer = plugin.TValue[string]{Data: "swp1", State: plugin.StateIsSet}
			res.Direction = plugin.TValue[string]{Data: tc.direction, State: plugin.StateIsSet}
			res.Vrf = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
			res.Afi = plugin.TValue[string]{Data: tc.afi, State: plugin.StateIsSet}
			res.Limit = plugin.TValue[int64]{Data: 10, State: plugin.StateIsSet}

			_, _, err := res.load()
			require.Error(t, err)
		})
	}
}
