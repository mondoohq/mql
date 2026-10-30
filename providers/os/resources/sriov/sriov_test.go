// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sriov_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/sriov"
)

const sysfsWalkOutput = `===PF===enp25s0f0
pciAddress=0000:19:00.0
driver=i40e
vendor=0x8086
device=0x1572
numa_node=0
sriov_numvfs=2
sriov_totalvfs=64
net.address=b4:96:91:aa:bb:cc
net.mtu=9000
net.operstate=up
===VF===0
pciAddress=0000:19:02.0
driver=iavf
vendor=0x8086
device=0x154c
numa_node=0
interface=enp25s2f0
===VF===1
pciAddress=0000:19:02.1
driver=vfio-pci
vendor=0x8086
device=0x154c
numa_node=0
===PF===enp25s0f1
pciAddress=0000:19:00.1
driver=i40e
vendor=0x8086
device=0x1572
numa_node=-1
sriov_numvfs=0
sriov_totalvfs=64
net.address=b4:96:91:aa:bb:cd
net.mtu=1500
net.operstate=down
`

func TestParseSysfs(t *testing.T) {
	pfs := sriov.ParseSysfs(sysfsWalkOutput)
	require.Len(t, pfs, 2)

	first := pfs[0]
	assert.Equal(t, "enp25s0f0", first.Interface)
	assert.Equal(t, "0000:19:00.0", first.PCIAddress)
	assert.Equal(t, "i40e", first.Driver)
	assert.Equal(t, "8086", first.VendorID)
	assert.Equal(t, "1572", first.DeviceID)
	assert.Equal(t, int64(2), first.NumVFs)
	assert.Equal(t, int64(64), first.TotalVFs)
	assert.Equal(t, "b4:96:91:aa:bb:cc", first.MACAddress)
	assert.Equal(t, int64(9000), first.MTU)
	assert.Equal(t, "up", first.OperationalState)
	assert.Equal(t, int64(0), first.NUMANode)
	require.Len(t, first.VirtualFunctions, 2)

	assert.Equal(t, int64(0), first.VirtualFunctions[0].Index)
	assert.Equal(t, "0000:19:02.0", first.VirtualFunctions[0].PCIAddress)
	assert.Equal(t, "iavf", first.VirtualFunctions[0].Driver)
	assert.Equal(t, "enp25s2f0", first.VirtualFunctions[0].Interface)
	assert.False(t, first.VirtualFunctions[0].UsesPassthroughDriver())

	// A virtual function bound to vfio-pci has no kernel interface.
	assert.Equal(t, "vfio-pci", first.VirtualFunctions[1].Driver)
	assert.Empty(t, first.VirtualFunctions[1].Interface)
	assert.True(t, first.VirtualFunctions[1].UsesPassthroughDriver())

	// A capable physical function with no virtual functions enabled reports an
	// empty list rather than a missing one.
	second := pfs[1]
	assert.Equal(t, int64(0), second.NumVFs)
	assert.Equal(t, int64(64), second.TotalVFs)
	assert.Equal(t, int64(-1), second.NUMANode)
	assert.Empty(t, second.VirtualFunctions)
}

func TestParseSysfsEmpty(t *testing.T) {
	assert.Empty(t, sriov.ParseSysfs(""))
	assert.Empty(t, sriov.ParseSysfs("\n\n"))
}

// TestParseSysfsMissingNumaNode pins the reading for a device whose sysfs has
// no numa_node file. The result must be the "no affinity" value, not node 0.
func TestParseSysfsMissingNumaNode(t *testing.T) {
	pfs := sriov.ParseSysfs("===PF===eth0\npciAddress=0000:01:00.0\nsriov_numvfs=1\n===VF===0\npciAddress=0000:01:02.0\n")
	require.Len(t, pfs, 1)
	assert.Equal(t, int64(-1), pfs[0].NUMANode)
	require.Len(t, pfs[0].VirtualFunctions, 1)
	assert.Equal(t, int64(-1), pfs[0].VirtualFunctions[0].NUMANode)
}

const linkShowJSON = `[
  {"ifindex":2,"ifname":"enp25s0f0","mtu":9000,
   "vfinfo_list":[
     {"vf":0,"link_type":"ether","address":"aa:00:00:00:00:01","broadcast":"ff:ff:ff:ff:ff:ff",
      "vlan_list":[{"vlan":101,"qos":3}],
      "rate":{"max_tx_rate":1000,"min_tx_rate":100},
      "spoofchk":true,"link_state":"auto","trust":false},
     {"vf":1,"link_type":"ether","address":"aa:00:00:00:00:02",
      "vlan_list":[{}],
      "rate":{"max_tx_rate":0,"min_tx_rate":0},
      "spoofchk":false,"link_state":"enable","trust":true}
   ]},
  {"ifindex":3,"ifname":"lo","mtu":65536}
]`

func TestParseLinkConfig(t *testing.T) {
	config, err := sriov.ParseLinkConfig(linkShowJSON)
	require.NoError(t, err)

	// Interfaces without virtual functions are absent, not empty.
	require.Len(t, config, 1)
	byIndex := config["enp25s0f0"]
	require.Len(t, byIndex, 2)

	assert.Equal(t, "aa:00:00:00:00:01", byIndex[0].MACAddress)
	assert.Equal(t, int64(101), byIndex[0].VlanID)
	assert.Equal(t, int64(3), byIndex[0].QoS)
	assert.True(t, byIndex[0].SpoofChecking)
	assert.False(t, byIndex[0].Trusted)
	assert.Equal(t, "auto", byIndex[0].LinkState)
	assert.Equal(t, int64(1000), byIndex[0].MaxTxRate)
	assert.Equal(t, int64(100), byIndex[0].MinTxRate)

	// Spoof checking off plus trust on is the permissive combination.
	assert.False(t, byIndex[1].SpoofChecking)
	assert.True(t, byIndex[1].Trusted)
	assert.Equal(t, int64(0), byIndex[1].VlanID)
}

// TestParseLinkConfigFlatShape pins the older iproute2 output, which reports
// the VLAN and the rates inline instead of in nested objects.
func TestParseLinkConfigFlatShape(t *testing.T) {
	config, err := sriov.ParseLinkConfig(`[
      {"ifname":"eth0","vfinfo_list":[
        {"vf":0,"address":"aa:00:00:00:00:03","vlan":7,"qos":1,
         "max_tx_rate":500,"min_tx_rate":50,"spoofchk":true,"trust":false,"link_state":"auto"}
      ]}
    ]`)
	require.NoError(t, err)

	vf := config["eth0"][0]
	assert.Equal(t, int64(7), vf.VlanID)
	assert.Equal(t, int64(1), vf.QoS)
	assert.Equal(t, int64(500), vf.MaxTxRate)
	assert.Equal(t, int64(50), vf.MinTxRate)
}

// TestParseLinkConfigNestedLinkInfo pins the shape where the virtual function
// list sits under linkinfo.info_data.
func TestParseLinkConfigNestedLinkInfo(t *testing.T) {
	config, err := sriov.ParseLinkConfig(`[
      {"ifname":"eth0","linkinfo":{"info_data":{"vfinfo_list":[{"vf":0,"spoofchk":true}]}}}
    ]`)
	require.NoError(t, err)
	require.Len(t, config, 1)
	assert.True(t, config["eth0"][0].SpoofChecking)
}

func TestParseLinkConfigEmptyAndInvalid(t *testing.T) {
	config, err := sriov.ParseLinkConfig("")
	require.NoError(t, err)
	assert.Empty(t, config)

	// A transport failure must be an error, not a silent "nothing configured".
	_, err = sriov.ParseLinkConfig("not json")
	require.Error(t, err)
}

func TestMerge(t *testing.T) {
	pfs := sriov.Merge(sriov.ParseSysfs(sysfsWalkOutput), mustParseLink(t, linkShowJSON))
	require.Len(t, pfs, 2)
	require.Len(t, pfs[0].VirtualFunctions, 2)

	first := pfs[0].VirtualFunctions[0]
	assert.True(t, first.LinkConfigured)
	assert.Equal(t, "aa:00:00:00:00:01", first.MACAddress)
	assert.True(t, first.SpoofChecking)
	// The sysfs values survive the merge.
	assert.Equal(t, "0000:19:02.0", first.PCIAddress)
	assert.Equal(t, "iavf", first.Driver)
}

// TestMergeKeepsUnreportedVirtualFunctions checks that a virtual function the
// link layer does not report is marked unconfigured rather than reported as
// having spoof checking off.
func TestMergeKeepsUnreportedVirtualFunctions(t *testing.T) {
	pfs := sriov.Merge(sriov.ParseSysfs(sysfsWalkOutput), mustParseLink(t, `[
      {"ifname":"enp25s0f0","vfinfo_list":[{"vf":0,"spoofchk":true}]}
    ]`))
	require.Len(t, pfs[0].VirtualFunctions, 2)

	assert.True(t, pfs[0].VirtualFunctions[0].LinkConfigured)
	assert.False(t, pfs[0].VirtualFunctions[1].LinkConfigured)
	assert.False(t, pfs[0].VirtualFunctions[1].SpoofChecking)
}

func mustParseLink(t *testing.T, raw string) map[string]map[int64]sriov.VirtualFunction {
	t.Helper()
	config, err := sriov.ParseLinkConfig(raw)
	require.NoError(t, err)
	return config
}
