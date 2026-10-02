// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ovs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/ovs"
)

// The three documents below are shaped like ovs-vsctl --format=json output on
// a node running the OVS CNI plugin: one bridge, its local port, and one pod
// interface carrying the container id in external_ids.
const bridgeJSON = `{
  "headings": ["_uuid","name","datapath_type","fail_mode","protocols","stp_enable","rstp_enable","external_ids","other_config","ports"],
  "data": [[
    ["uuid","b0000000-0000-0000-0000-00000000000b"],
    "br-ex",
    "system",
    "secure",
    ["set",["OpenFlow13","OpenFlow15"]],
    false,
    false,
    ["map",[["bridge-id","br-ex"]]],
    ["map",[]],
    ["set",[["uuid","p0000000-0000-0000-0000-00000000000a"],["uuid","p0000000-0000-0000-0000-00000000000b"]]]
  ]]
}`

const portJSON = `{
  "headings": ["_uuid","name","vlan_mode","tag","trunks","external_ids","other_config","interfaces"],
  "data": [
    [
      ["uuid","p0000000-0000-0000-0000-00000000000a"],
      "br-ex",
      ["set",[]],
      ["set",[]],
      ["set",[]],
      ["map",[]],
      ["map",[]],
      ["uuid","i0000000-0000-0000-0000-00000000000a"]
    ],
    [
      ["uuid","p0000000-0000-0000-0000-00000000000b"],
      "veth-pod0",
      "access",
      101,
      ["set",[]],
      ["map",[["contIface","net1"]]],
      ["map",[]],
      ["set",[["uuid","i0000000-0000-0000-0000-00000000000b"]]]
    ],
    [
      ["uuid","p0000000-0000-0000-0000-00000000000c"],
      "orphan",
      ["set",[]],
      ["set",[]],
      ["set",[]],
      ["map",[]],
      ["map",[]],
      ["set",[]]
    ]
  ]
}`

const interfaceJSON = `{
  "headings": ["_uuid","name","type","admin_state","link_state","mac_in_use","mtu","ofport","error","external_ids","options"],
  "data": [
    [
      ["uuid","i0000000-0000-0000-0000-00000000000a"],
      "br-ex","internal","up","up","aa:bb:cc:00:00:01",1500,65534,["set",[]],["map",[]],["map",[]]
    ],
    [
      ["uuid","i0000000-0000-0000-0000-00000000000b"],
      "veth-pod0","","up","up","aa:bb:cc:00:00:02",9000,3,["set",[]],
      ["map",[["contIface","net1"],["ovs-cni.network.kubevirt.io/pod","workloads/dpdk-app-0"]]],
      ["map",[]]
    ],
    [
      ["uuid","i0000000-0000-0000-0000-00000000000c"],
      "broken","system","down","down","",1500,-1,"could not open network device broken (No such device)",["map",[]],["map",[]]
    ]
  ]
}`

func TestParseTopology(t *testing.T) {
	topology, err := ovs.ParseTopology(bridgeJSON, portJSON, interfaceJSON)
	require.NoError(t, err)

	require.Len(t, topology.Bridges, 1)
	bridge := topology.Bridges[0]
	assert.Equal(t, "br-ex", bridge.Name)
	assert.Equal(t, "system", bridge.DatapathType)
	assert.Equal(t, "secure", bridge.FailMode)
	assert.Equal(t, []string{"OpenFlow13", "OpenFlow15"}, bridge.Protocols)
	assert.False(t, bridge.STPEnabled)
	assert.Equal(t, map[string]string{"bridge-id": "br-ex"}, bridge.ExternalIDs)
	// An empty map column reads as no map, not as an empty one.
	assert.Nil(t, bridge.OtherConfig)
	assert.Len(t, bridge.PortUUIDs, 2)

	require.Len(t, topology.Ports, 3)
	local := topology.Ports[0]
	assert.Equal(t, "br-ex", local.Name)
	assert.Equal(t, "br-ex", local.BridgeName)
	// An unset VLAN tag must not read as VLAN 0.
	assert.False(t, local.Tagged)
	assert.Equal(t, int64(0), local.Tag)

	pod := topology.Ports[1]
	assert.Equal(t, "access", pod.VlanMode)
	assert.True(t, pod.Tagged)
	assert.Equal(t, int64(101), pod.Tag)
	// A single-member set is written as the bare value by OVSDB.
	assert.Len(t, topology.Ports[0].InterfaceUUIDs, 1)

	// A port no bridge references is reported with an empty bridge name.
	assert.Empty(t, topology.Ports[2].BridgeName)

	require.Len(t, topology.Interfaces, 3)
	assert.Equal(t, "br-ex", topology.Interfaces[0].PortName)
	assert.Equal(t, "internal", topology.Interfaces[0].Type)
	assert.Equal(t, int64(65534), topology.Interfaces[0].OFPort)

	podInterface := topology.Interfaces[1]
	assert.Equal(t, "veth-pod0", podInterface.PortName)
	assert.Equal(t, "br-ex", podInterface.BridgeName)
	assert.Equal(t, int64(9000), podInterface.MTU)
	assert.Equal(t, "workloads/dpdk-app-0", podInterface.ExternalIDs["ovs-cni.network.kubevirt.io/pod"])
	assert.Empty(t, podInterface.Error)

	// An interface the switch could not open reports the error text.
	broken := topology.Interfaces[2]
	assert.Equal(t, "could not open network device broken (No such device)", broken.Error)
	assert.Equal(t, "down", broken.LinkState)
	assert.Empty(t, broken.PortName)
}

func TestParseTopologyEmpty(t *testing.T) {
	topology, err := ovs.ParseTopology("", "", "")
	require.NoError(t, err)
	assert.Empty(t, topology.Bridges)
	assert.Empty(t, topology.Ports)
	assert.Empty(t, topology.Interfaces)
}

func TestParseTopologyRejectsBadInput(t *testing.T) {
	_, err := ovs.ParseTopology("ovs-vsctl: command not found", "", "")
	require.Error(t, err)

	// A row with fewer values than columns would silently shift every field,
	// so it must fail rather than produce a wrong reading.
	_, err = ovs.ParseTopology(`{"headings":["_uuid","name"],"data":[[["uuid","x"]]]}`, "", "")
	require.Error(t, err)
}

func TestParseVersion(t *testing.T) {
	assert.Equal(t, "3.3.0", ovs.ParseVersion("ovs-vsctl (Open vSwitch) 3.3.0\nDB Schema 8.5.0\n"))
	assert.Empty(t, ovs.ParseVersion(""))
	assert.Empty(t, ovs.ParseVersion("\n  \n"))
}

func TestVsctlFailure(t *testing.T) {
	// ovs-vsctl run as a user that cannot open the database socket, captured
	// on Ubuntu 16.04 through 24.04 with Open vSwitch running
	err := ovs.VsctlFailure(1, "ovs-vsctl: unix:/var/run/openvswitch/db.sock: database connection failed (Permission denied)\n")
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrForbidden)
	assert.Contains(t, err.Error(), "database connection failed (Permission denied)")

	// ovsdb-server stopped: the socket is gone
	err = ovs.VsctlFailure(1, "ovs-vsctl: unix:/var/run/openvswitch/db.sock: database connection failed (No such file or directory)\n")
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrTargetUnavailable)

	// ovsdb-server killed without removing its socket
	err = ovs.VsctlFailure(1, "ovs-vsctl: unix:/var/run/openvswitch/db.sock: database connection failed (Connection refused)\n")
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrTargetUnavailable)

	// anything else is a failure, but not one we can classify
	err = ovs.VsctlFailure(1, "ovs-vsctl: no row \"x\" in table Bridge\n")
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	assert.Contains(t, err.Error(), "exit code 1")
	assert.Contains(t, err.Error(), `no row "x" in table Bridge`)

	// no stderr at all still reports the exit code
	err = ovs.VsctlFailure(2, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit code 2")
}
