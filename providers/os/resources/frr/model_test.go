// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func neighborByName(n []Neighbor, name string) *Neighbor {
	for i := range n {
		if n[i].Name == name {
			return &n[i]
		}
	}
	return nil
}

func bgpByVRF(list []BGP, vrf string) *BGP {
	for i := range list {
		if list[i].VRF == vrf {
			return &list[i]
		}
	}
	return nil
}

func afByName(list []AddressFamily, afi, safi string) *AddressFamily {
	for i := range list {
		if list[i].AFI == afi && list[i].SAFI == safi {
			return &list[i]
		}
	}
	return nil
}

func vrfByName(list []VRF, name string) *VRF {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func TestBGPInstances_PlainSetup(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	instances := cfg.BGPInstances()
	require.Len(t, instances, 1)

	b := instances[0]
	assert.Equal(t, int64(65500), b.ASN)
	assert.Equal(t, "", b.VRF)
	assert.Equal(t, "192.0.2.10", b.RouterID)
	// Both defaults are switched off by an explicit `no` line.
	assert.False(t, b.EbgpRequiresPolicy)
	assert.False(t, b.DefaultIPv4Unicast)
	assert.Len(t, b.AddressFamilies, 2)
}

func TestNeighbors_UnnumberedAndPeerGroups(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	b := cfg.BGPInstances()[0]

	dcgw1 := neighborByName(b.Neighbors, "eth-dcgw1")
	require.NotNil(t, dcgw1)
	assert.True(t, dcgw1.Interface)
	assert.Equal(t, "64497", dcgw1.RemoteAs)
	assert.Equal(t, int64(64497), dcgw1.RemoteASN)

	group := neighborByName(b.Neighbors, "server")
	require.NotNil(t, group)
	assert.True(t, group.IsPeerGroup)
	assert.Equal(t, int64(65501), group.RemoteASN)
	assert.True(t, group.BFD)
	assert.True(t, group.PasswordSet)
	assert.Equal(t, int64(3), group.KeepaliveTime)
	assert.Equal(t, int64(9), group.HoldTime)

	member := neighborByName(b.Neighbors, "eth-srv1")
	require.NotNil(t, member)
	assert.Equal(t, "server", member.PeerGroup)
	assert.True(t, member.Interface)

	transit := neighborByName(b.Neighbors, "198.51.100.7")
	require.NotNil(t, transit)
	assert.False(t, transit.Interface)
	assert.Equal(t, "transit peer", transit.Description)
	assert.Equal(t, int64(2), transit.TTLSecurityHops)
}

// TestNeighbors_InboundFilterAudit covers the first audit question: does a
// BGP session accept routes without a prefix filter.
func TestNeighbors_InboundFilterAudit(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	b := cfg.BGPInstances()[0]

	filtered := neighborByName(b.Neighbors, "eth-dcgw1")
	require.NotNil(t, filtered)
	assert.Equal(t, []string{"pl_fabric_in", "pl_fabric_in6"}, filtered.PrefixListsIn)
	assert.Equal(t, []string{"rm_fabric_out"}, filtered.RouteMapsOut)
	assert.Equal(t, []string{"ipv4 unicast", "ipv6 unicast"}, filtered.ActivatedAddressFamilies)

	ipv4 := filtered.AddressFamilies[0]
	assert.Equal(t, "ipv4", ipv4.AFI)
	assert.True(t, ipv4.Activate)
	assert.Equal(t, int64(1000), ipv4.MaximumPrefix)

	// The transit peer is activated without any inbound filter, which is the
	// finding a policy has to catch.
	transit := neighborByName(b.Neighbors, "198.51.100.7")
	require.NotNil(t, transit)
	assert.Empty(t, transit.PrefixListsIn)
	assert.Empty(t, transit.RouteMapsIn)
	assert.Empty(t, transit.FilterListsIn)
	assert.Equal(t, []string{"ipv4 unicast"}, transit.ActivatedAddressFamilies)
}

func TestPrefixLists(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	lists := cfg.PrefixLists()
	require.Len(t, lists, 2)

	assert.Equal(t, "pl_fabric_in", lists[0].Name)
	assert.Equal(t, "ip", lists[0].AFI)
	require.Len(t, lists[0].Entries, 2)
	assert.Equal(t, int64(5), lists[0].Entries[0].Seq)
	assert.Equal(t, "permit", lists[0].Entries[0].Action)
	assert.Equal(t, "10.0.0.0/8", lists[0].Entries[0].Prefix)
	assert.Equal(t, int64(24), lists[0].Entries[0].Le)
	assert.Equal(t, "deny", lists[0].Entries[1].Action)

	assert.Equal(t, "ipv6", lists[1].AFI)
	assert.Equal(t, "pl_fabric_in6", lists[1].Name)
}

func TestRouteMaps(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	maps := cfg.RouteMaps()
	require.Len(t, maps, 1)

	rm := maps[0]
	assert.Equal(t, "rm_fabric_out", rm.Name)
	require.Len(t, rm.Entries, 2)
	assert.Equal(t, "permit", rm.Entries[0].Action)
	assert.Equal(t, int64(10), rm.Entries[0].Sequence)
	assert.Equal(t, []string{"ip address prefix-list pl_fabric_in"}, rm.Entries[0].Match)
	assert.Equal(t, []string{"community 65500:100 additive"}, rm.Entries[0].Set)
	assert.Equal(t, "deny", rm.Entries[1].Action)
}

func TestInterfaces(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	ifaces := cfg.Interfaces()
	require.Len(t, ifaces, 2)

	assert.Equal(t, "lo", ifaces[0].Name)
	assert.Equal(t, []string{"192.0.2.10/32"}, ifaces[0].IPAddresses)

	assert.Equal(t, "eth-dcgw1", ifaces[1].Name)
	assert.Equal(t, "uplink to dcgw1", ifaces[1].Description)
	assert.False(t, ifaces[1].Shutdown)
}

func TestBGPInstances_EVPNSetup(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")
	instances := cfg.BGPInstances()
	require.Len(t, instances, 5)

	underlay := bgpByVRF(instances, "")
	require.NotNil(t, underlay)
	assert.Equal(t, int64(65100), underlay.ASN)

	evpn := afByName(underlay.AddressFamilies, "l2vpn", "evpn")
	require.NotNil(t, evpn)
	assert.True(t, evpn.AdvertiseAllVNI)
	require.Len(t, evpn.VNIs, 1)
	assert.Equal(t, int64(4001), evpn.VNIs[0].ID)
	assert.Equal(t, []string{"65100:4001"}, evpn.VNIs[0].RouteTargetsImport)
	assert.Equal(t, []string{"65100:4001"}, evpn.VNIs[0].RouteTargetsExport)

	ipv4 := afByName(underlay.AddressFamilies, "ipv4", "unicast")
	require.NotNil(t, ipv4)
	assert.Equal(t, []string{"192.0.2.30/32"}, ipv4.Networks)

	cluster := bgpByVRF(instances, "cluster")
	require.NotNil(t, cluster)
	clusterV4 := afByName(cluster.AddressFamilies, "ipv4", "unicast")
	require.NotNil(t, clusterV4)
	assert.Equal(t, []string{"vr.mgmt"}, clusterV4.ImportVrfs)
	assert.Equal(t, "rm_cluster_import", clusterV4.ImportVrfRouteMap)
	assert.Equal(t, []string{"connected", "static", "kernel"}, clusterV4.Redistribute)

	clusterEVPN := afByName(cluster.AddressFamilies, "l2vpn", "evpn")
	require.NotNil(t, clusterEVPN)
	assert.Equal(t, []string{
		"ipv4 unicast route-map rm_export_local",
		"ipv6 unicast route-map rm_export_local",
	}, clusterEVPN.Advertise)
}

// TestVRFs_TenantSeparation covers the second and third audit questions: are
// tenant VRFs separated, and do route targets leak between them.
func TestVRFs_TenantSeparation(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")
	vrfs := cfg.VRFs()
	require.Len(t, vrfs, 4)

	cluster := vrfByName(vrfs, "cluster")
	require.NotNil(t, cluster)
	assert.Equal(t, int64(5000), cluster.VNI)
	assert.Equal(t, int64(65100), cluster.RouterASN)
	assert.Equal(t, []string{"10.100.0.0/16 blackhole"}, cluster.StaticRoutes)
	assert.Equal(t, []string{"vr.mgmt"}, cluster.ImportedVrfs)
	assert.Equal(t, []string{"65100:5000"}, cluster.RouteTargetsImport)

	blue := vrfByName(vrfs, "t-blue")
	require.NotNil(t, blue)
	assert.Equal(t, int64(5010), blue.VNI)
	// The blue tenant imports no other VRF, so it stays separate.
	assert.Empty(t, blue.ImportedVrfs)
	assert.Equal(t, []string{"65100:5010"}, blue.RouteTargetsImport)
	assert.Equal(t, []string{"65100:5010"}, blue.RouteTargetsExport)

	green := vrfByName(vrfs, "t-green")
	require.NotNil(t, green)
	// Green imports the route target blue exports, which leaks blue routes
	// into the green tenant.
	assert.Equal(t, []string{"65100:5010", "65100:5020"}, green.RouteTargetsImport)
	assert.Equal(t, []string{"65100:5020"}, green.RouteTargetsExport)

	var leaked []string
	for _, rt := range green.RouteTargetsImport {
		for _, ex := range blue.RouteTargetsExport {
			if rt == ex {
				leaked = append(leaked, rt)
			}
		}
	}
	assert.Equal(t, []string{"65100:5010"}, leaked)
}

func TestVRFNeighbors_FilterRollup(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")
	instances := cfg.BGPInstances()

	blue := bgpByVRF(instances, "t-blue")
	require.NotNil(t, blue)
	peer := neighborByName(blue.Neighbors, "203.0.113.5")
	require.NotNil(t, peer)
	assert.Equal(t, []string{"203-0-113-5-ipv4-in"}, peer.RouteMapsIn)
	assert.Equal(t, []string{"203-0-113-5-ipv4-out"}, peer.RouteMapsOut)
	assert.Equal(t, int64(100), peer.AddressFamilies[0].MaximumPrefix)

	green := bgpByVRF(instances, "t-green")
	require.NotNil(t, green)
	unfiltered := neighborByName(green.Neighbors, "203.0.113.9")
	require.NotNil(t, unfiltered)
	assert.Empty(t, unfiltered.RouteMapsIn)
	assert.Empty(t, unfiltered.PrefixListsIn)
	assert.Equal(t, int64(0), unfiltered.AddressFamilies[0].MaximumPrefix)
}

func TestInterfaces_HBNPolicyRouting(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")
	ifaces := cfg.Interfaces()
	require.Len(t, ifaces, 2)

	assert.Equal(t, "hbn", ifaces[0].Name)
	assert.Equal(t, "hbn", ifaces[0].PBRPolicy)
	assert.Equal(t, "lo", ifaces[1].Name)
	assert.Equal(t, []string{"192.0.2.30/32"}, ifaces[1].IPAddresses)
}

func TestRouteMaps_EVPNSetup(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")
	maps := cfg.RouteMaps()

	var names []string
	for _, m := range maps {
		names = append(names, m.Name)
	}
	assert.Equal(t, []string{
		"TAG-FABRIC-IN", "DENY-TAG-FABRIC-OUT", "rm_cluster_import",
		"rm_t-blue_import", "rm_export_local",
	}, names)

	var importMap *RouteMap
	for i := range maps {
		if maps[i].Name == "rm_t-blue_import" {
			importMap = &maps[i]
		}
	}
	require.NotNil(t, importMap)
	require.Len(t, importMap.Entries, 1)
	assert.Equal(t, "rm_t-blue_import_cluster", importMap.Entries[0].Call)
	assert.Equal(t, []string{"source-vrf cluster"}, importMap.Entries[0].Match)
}

// TestNeighbors_ListenRangeWithoutGroup pins that a listen range without a
// peer group creates no neighbor. An empty name would show up as a real
// peer and would swallow every later line that names no peer.
func TestNeighbors_ListenRangeWithoutGroup(t *testing.T) {
	src := `hostname x
router bgp 65100
 bgp listen range 10.50.0.0/16
 neighbor swp1 interface remote-as 65000
exit
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	instances := cfg.BGPInstances()
	require.Len(t, instances, 1)

	require.Len(t, instances[0].Neighbors, 1)
	assert.Equal(t, "swp1", instances[0].Neighbors[0].Name)

	// The complete form still builds the dynamic group.
	src = `hostname x
router bgp 65100
 bgp listen range 10.50.0.0/16 peer-group EVPN
exit
`
	cfg, err = Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	instances = cfg.BGPInstances()
	require.Len(t, instances[0].Neighbors, 1)
	assert.Equal(t, "EVPN", instances[0].Neighbors[0].Name)
	assert.Equal(t, "10.50.0.0/16", instances[0].Neighbors[0].ListenRange)
	assert.True(t, instances[0].Neighbors[0].IsPeerGroup)
}

func TestNeighbors_NegatedSettingsClearPreviousValues(t *testing.T) {
	src := `hostname x
router bgp 65100
 neighbor GROUP peer-group
 neighbor PEER peer-group GROUP
 address-family ipv4 unicast
  neighbor PEER activate
  neighbor PEER route-map rm-in in
  neighbor PEER route-map rm-out out
  neighbor PEER prefix-list pl-in in
  neighbor PEER prefix-list pl-out out
  neighbor PEER filter-list fl-in in
  neighbor PEER filter-list fl-out out
  neighbor PEER maximum-prefix 100
  no neighbor PEER route-map rm-in in
  no neighbor PEER route-map rm-out out
  no neighbor PEER prefix-list pl-in in
  no neighbor PEER prefix-list pl-out out
  no neighbor PEER filter-list fl-in in
  no neighbor PEER filter-list fl-out out
  no neighbor PEER maximum-prefix
 exit-address-family
 no neighbor GROUP peer-group
 no neighbor PEER peer-group GROUP
exit
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.BGPInstances(), 1)

	neighbors := cfg.BGPInstances()[0].Neighbors
	group := neighborByName(neighbors, "GROUP")
	require.NotNil(t, group)
	assert.False(t, group.IsPeerGroup)

	peer := neighborByName(neighbors, "PEER")
	require.NotNil(t, peer)
	assert.Empty(t, peer.PeerGroup)
	require.Len(t, peer.AddressFamilies, 1)
	assert.Empty(t, peer.RouteMapsIn)
	assert.Empty(t, peer.RouteMapsOut)
	assert.Empty(t, peer.PrefixListsIn)
	assert.Empty(t, peer.PrefixListsOut)
	assert.Empty(t, peer.FilterListsIn)
	assert.Empty(t, peer.FilterListsOut)
	assert.Zero(t, peer.AddressFamilies[0].MaximumPrefix)
}
