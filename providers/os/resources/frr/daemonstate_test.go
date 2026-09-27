// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOSPFNeighbors(t *testing.T) {
	neighbors, err := ParseOSPFNeighbors(2, readFixture(t, "show_ip_ospf_neighbor.json"))
	require.NoError(t, err)
	require.Len(t, neighbors, 2)

	full := neighbors[0]
	assert.Equal(t, int64(2), full.Version)
	assert.Equal(t, "192.0.2.31", full.NeighborID)
	// FRR prints the role after a slash, and both parts are addressable.
	assert.Equal(t, "Full", full.State)
	assert.Equal(t, "DR", full.Role)
	assert.True(t, full.Full)
	assert.Equal(t, "swp1", full.Interface)
	assert.Equal(t, "10.0.0.2", full.Address)
	assert.Equal(t, "10.0.0.1", full.LocalAddress)
	assert.Equal(t, int64(4365000), full.UptimeMsec)
	assert.Equal(t, int64(35000), full.DeadTimeMsec)
	assert.Equal(t, int64(0), full.RetransmitCount)

	// An adjacency stuck before Full carries no traffic, which is the
	// finding a policy looks for.
	stuck := neighbors[1]
	assert.Equal(t, "ExStart", stuck.State)
	assert.False(t, stuck.Full)
	assert.Equal(t, "DROther", stuck.Role)
	assert.Equal(t, int64(4), stuck.RetransmitCount)
}

// TestParseOSPFNeighbors_V3Shape covers OSPFv3, which prints an array where
// OSPF prints a map of arrays.
func TestParseOSPFNeighbors_V3Shape(t *testing.T) {
	neighbors, err := ParseOSPFNeighbors(3, readFixture(t, "show_ipv6_ospf6_neighbor.json"))
	require.NoError(t, err)
	require.Len(t, neighbors, 1)

	n := neighbors[0]
	assert.Equal(t, int64(3), n.Version)
	assert.Equal(t, "192.0.2.31", n.NeighborID)
	assert.Equal(t, "Full", n.State)
	assert.True(t, n.Full)
	assert.Equal(t, "swp1", n.Interface)
	assert.Equal(t, int64(4365000), n.UptimeMsec)
	assert.Equal(t, int64(40000), n.DeadTimeMsec)
}

func TestParseOSPFNeighbors_Empty(t *testing.T) {
	neighbors, err := ParseOSPFNeighbors(2, []byte(`{"neighbors":{}}`))
	require.NoError(t, err)
	assert.Empty(t, neighbors)

	// A router without the daemon prints an object without the member.
	neighbors, err = ParseOSPFNeighbors(2, []byte(`{}`))
	require.NoError(t, err)
	assert.Empty(t, neighbors)

	_, err = ParseOSPFNeighbors(2, []byte(`not json`))
	require.Error(t, err)
}

func TestParseISISNeighbors(t *testing.T) {
	neighbors, err := ParseISISNeighbors(readFixture(t, "show_isis_neighbor.json"))
	require.NoError(t, err)
	// The circuit without an adjacency is not a neighbor.
	require.Len(t, neighbors, 2)

	up := neighbors[0]
	assert.Equal(t, "FABRIC", up.Area)
	assert.Equal(t, "spine1", up.SystemID)
	assert.Equal(t, "swp2", up.Interface)
	assert.Equal(t, "2", up.Level)
	assert.Equal(t, "Up", up.State)
	assert.True(t, up.Up)
	assert.Equal(t, "27s", up.ExpiresIn)
	assert.Equal(t, "aa:bb:cc:00:01:02", up.SNPA)

	assert.Equal(t, "Init", neighbors[1].State)
	assert.False(t, neighbors[1].Up)
}

// TestParseISISNeighbors_FlatShape covers the older versions that print the
// circuit details next to the adjacency instead of in an object.
func TestParseISISNeighbors_FlatShape(t *testing.T) {
	src := []byte(`{"areas":[{"area":"FABRIC","circuits":[
		{"circuit":0,"adj":"spine1","name":"swp2","state":"Up","level":"2"}]}]}`)
	neighbors, err := ParseISISNeighbors(src)
	require.NoError(t, err)
	require.Len(t, neighbors, 1)
	assert.Equal(t, "swp2", neighbors[0].Interface)
	assert.True(t, neighbors[0].Up)
}

func TestParseBFDSessions(t *testing.T) {
	sessions, err := ParseBFDSessions(readFixture(t, "show_bfd_peers.json"))
	require.NoError(t, err)
	require.Len(t, sessions, 2)

	up := sessions[0]
	assert.Equal(t, "192.0.2.31", up.Peer)
	assert.Equal(t, "192.0.2.30", up.Local)
	assert.Equal(t, "default", up.VRF)
	assert.Equal(t, "swp1", up.Interface)
	assert.False(t, up.MultiHop)
	assert.True(t, up.Up)
	assert.Equal(t, int64(4365), up.UptimeSec)
	assert.Equal(t, int64(3), up.DetectMulti)
	assert.Equal(t, int64(300), up.ReceiveMsec)
	assert.Equal(t, int64(300), up.TransmitMsec)
	assert.Equal(t, int64(50), up.EchoMsec)

	// A session that is down carries the reason, and the remote timers say
	// what the peer asked for.
	down := sessions[1]
	assert.True(t, down.MultiHop)
	assert.False(t, down.Up)
	assert.Equal(t, "cluster", down.VRF)
	assert.Equal(t, "control detection time expired", down.Diagnostic)
	assert.Equal(t, int64(5), down.RemoteDetectMulti)
	assert.Equal(t, int64(300), down.RemoteReceiveMsec)
}

func TestParseBFDSessions_Empty(t *testing.T) {
	sessions, err := ParseBFDSessions([]byte(`[]`))
	require.NoError(t, err)
	assert.Empty(t, sessions)

	_, err = ParseBFDSessions([]byte(`{}`))
	require.Error(t, err)
}

func TestParseZebraInterfaces(t *testing.T) {
	ifaces, err := ParseZebraInterfaces(readFixture(t, "show_interface.json"))
	require.NoError(t, err)
	require.Len(t, ifaces, 2)

	up := ifaces[0]
	assert.Equal(t, "swp1", up.Name)
	assert.True(t, up.AdminUp)
	assert.True(t, up.OperUp)
	assert.Equal(t, "default", up.VRF)
	assert.Equal(t, int64(3), up.IfIndex)
	assert.Equal(t, int64(9216), up.MTU)
	assert.Equal(t, int64(25000), up.Speed)
	assert.Equal(t, "aa:bb:cc:00:00:03", up.HardwareAddress)
	assert.Equal(t, []string{"192.0.2.30/31"}, up.Addresses)
	assert.Equal(t, int64(0), up.LinkDowns)

	// A link that went down seven times is flapping, and an interface a
	// protocol took down is not the same as one an operator shut.
	flapping := ifaces[1]
	assert.Equal(t, "vlan100", flapping.Name)
	assert.True(t, flapping.AdminUp)
	assert.False(t, flapping.OperUp)
	assert.True(t, flapping.ProtocolDown)
	assert.Equal(t, int64(7), flapping.LinkDowns)
	assert.Equal(t, "cluster", flapping.VRF)
	assert.Equal(t, []string{"10.100.0.1/24"}, flapping.Addresses)
}
