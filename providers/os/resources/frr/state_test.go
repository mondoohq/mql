// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

func peerFor(peers []BGPPeer, name, afi string) *BGPPeer {
	for i := range peers {
		if peers[i].Name == name && peers[i].AFI == afi {
			return &peers[i]
		}
	}
	return nil
}

func TestValidateName(t *testing.T) {
	valid := []string{"cluster", "vr.mgmt", "t-blue", "VRF_1", "a"}
	for _, v := range valid {
		assert.NoError(t, ValidateName("vrf", v), v)
	}

	// A name that reaches the command line must not be able to change it.
	// The characters between `%` and `-` in ASCII are listed on purpose, so
	// a character class that was read as a range would fail here.
	invalid := []string{
		"", "-lead", ".lead", "a b", "a;id", "a$(id)", "a`id`", "a|b", "a\nb",
		"a'b", "a\"b", "../etc", "a&b", "a(b", "a)b", "a*b", "a+b", "a,b",
		strings.Repeat("a", 65),
	}
	for _, v := range invalid {
		assert.Error(t, ValidateName("vrf", v), "%q must be rejected", v)
	}
}

func TestParseBGPSummary(t *testing.T) {
	peers, err := ParseBGPSummary("", readFixture(t, "show_bgp_summary.json"))
	require.NoError(t, err)
	// Two peers in two address families.
	require.Len(t, peers, 4)

	up := peerFor(peers, "swp1", "ipv4")
	require.NotNil(t, up)
	assert.Equal(t, "unicast", up.SAFI)
	assert.Equal(t, int64(65000), up.RemoteAS)
	assert.Equal(t, int64(65100), up.LocalAS)
	assert.Equal(t, "leaf1", up.Hostname)
	assert.Equal(t, "Established", up.State)
	assert.True(t, up.Established)
	assert.Equal(t, int64(4365000), up.UptimeMsec)
	assert.Equal(t, int64(1042), up.MessagesReceived)
	assert.Equal(t, int64(5), up.PrefixesReceived)
	assert.Equal(t, int64(3), up.PrefixesSent)
	assert.Equal(t, "interface", up.IDType)

	down := peerFor(peers, "swp2", "ipv4")
	require.NotNil(t, down)
	assert.False(t, down.Established)
	assert.Equal(t, "Idle", down.State)
	assert.Equal(t, int64(3), down.ConnectionsDropped)

	evpn := peerFor(peers, "swp1", "l2vpn")
	require.NotNil(t, evpn)
	assert.Equal(t, "evpn", evpn.SAFI)
	assert.Equal(t, int64(24), evpn.PrefixesReceived)
}

func TestParseBGPSummary_VRFName(t *testing.T) {
	// A VRF summary carries the VRF name in every address family.
	src := []byte(`{"ipv4Unicast":{"vrfName":"t-blue","as":65100,"peers":{
		"203.0.113.5":{"remoteAs":65200,"state":"Established","pfxRcd":2,"pfxSnt":4,"idType":"ipv4"}}}}`)
	peers, err := ParseBGPSummary("t-blue", src)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	assert.Equal(t, "t-blue", peers[0].VRF)
	assert.Equal(t, "203.0.113.5", peers[0].Name)
	assert.Equal(t, int64(2), peers[0].PrefixesReceived)
}

func TestEnrichBGPPeers(t *testing.T) {
	peers, err := ParseBGPSummary("", readFixture(t, "show_bgp_summary.json"))
	require.NoError(t, err)
	require.NoError(t, EnrichBGPPeers(peers, readFixture(t, "show_bgp_neighbors.json")))

	up := peerFor(peers, "swp1", "ipv4")
	require.NotNil(t, up)
	assert.Equal(t, "TAG-FABRIC-IN", up.RouteMapIn)
	assert.Equal(t, "DENY-TAG-FABRIC-OUT", up.RouteMapOut)
	assert.Equal(t, int64(5), up.PrefixesAccepted)
	assert.Equal(t, int64(3), up.PrefixesSent)
	// The peer announced 9 prefixes and 5 were kept, so the inbound policy
	// dropped 4.
	assert.True(t, up.PrefixesFilteredKnown)
	assert.Equal(t, int64(4), up.PrefixesFiltered)
	assert.NotNil(t, up.Details)
	assert.Equal(t, float64(1), up.Details["updateGroupId"])

	// Without an announced counter the filtered count stays unknown, which
	// must not be read as zero.
	down := peerFor(peers, "swp2", "ipv4")
	require.NotNil(t, down)
	assert.Equal(t, "pl_fabric_in", down.PrefixListIn)
	assert.False(t, down.PrefixesFilteredKnown)
	assert.Equal(t, int64(0), down.PrefixesFiltered)

	// The EVPN family of the same peer is enriched from its own object.
	evpn := peerFor(peers, "swp1", "l2vpn")
	require.NotNil(t, evpn)
	assert.Equal(t, int64(24), evpn.PrefixesAccepted)
	assert.Equal(t, int64(9), evpn.PrefixesSent)
}

func TestEnrichBGPPeers_DirectFilteredCounter(t *testing.T) {
	peers := []BGPPeer{{Name: "swp1", AFI: "ipv4", SAFI: "unicast", PrefixesAccepted: 5}}
	src := []byte(`{"swp1":{"addressFamilyInfo":{"ipv4Unicast":{"filteredPrefixCounter":7}}}}`)
	require.NoError(t, EnrichBGPPeers(peers, src))
	assert.True(t, peers[0].PrefixesFilteredKnown)
	assert.Equal(t, int64(7), peers[0].PrefixesFiltered)
}

func TestStreamRoutes(t *testing.T) {
	table, err := StreamRoutes(bytes.NewReader(readFixture(t, "show_ip_route.json")), 0)
	require.NoError(t, err)

	assert.Equal(t, int64(3), table.Total)
	assert.False(t, table.Truncated)
	// The cluster prefix has two entries, so four routes come from three
	// prefixes.
	require.Len(t, table.Entries, 4)

	def := table.Entries[0]
	assert.Equal(t, "0.0.0.0/0", def.Prefix)
	assert.Equal(t, "bgp", def.Protocol)
	assert.Equal(t, "default", def.VRF)
	assert.Equal(t, int64(254), def.Table)
	assert.True(t, def.Selected)
	assert.True(t, def.Installed)
	assert.Equal(t, int64(20), def.Distance)
	require.Len(t, def.Nexthops, 1)
	assert.Equal(t, "192.0.2.1", def.Nexthops[0].IP)
	assert.Equal(t, "swp1", def.Nexthops[0].Interface)
	assert.True(t, def.Nexthops[0].FIB)

	connected := table.Entries[1]
	assert.Equal(t, "connected", connected.Protocol)
	assert.True(t, connected.Nexthops[0].DirectlyConnected)

	vrfRoute := table.Entries[2]
	assert.Equal(t, "cluster", vrfRoute.VRF)
	assert.Equal(t, int64(1005), vrfRoute.Table)
	assert.Equal(t, "static", vrfRoute.Protocol)
	assert.False(t, vrfRoute.Installed)
	assert.Equal(t, "cluster", table.Entries[3].Nexthops[0].VRF)
}

// TestStreamRoutes_Bounded pins the bound. A fabric node can hold a full
// table, so the decoder must stop building entries and still count the rest.
func TestStreamRoutes_Bounded(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("{")
	const prefixes = 500
	for i := 0; i < prefixes; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, `"10.%d.%d.0/24":[{"prefix":"10.%d.%d.0/24","prefixLen":24,`+
			`"protocol":"bgp","vrfName":"default","table":254,"selected":true,`+
			`"nexthops":[{"ip":"192.0.2.1","interfaceName":"swp1","active":true,"fib":true}]}]`,
			i/256, i%256, i/256, i%256)
	}
	buf.WriteString("}")

	table, err := StreamRoutes(bytes.NewReader(buf.Bytes()), 10)
	require.NoError(t, err)
	assert.Len(t, table.Entries, 10)
	assert.True(t, table.Truncated)
	// Every prefix is counted, including the ones that built no entry.
	assert.Equal(t, int64(prefixes), table.Total)
	assert.Equal(t, "10.0.0.0/24", table.Entries[0].Prefix)
}

func TestStreamRoutes_EmptyAndBroken(t *testing.T) {
	// FRR prints an empty object for an empty table.
	table, err := StreamRoutes(strings.NewReader("{}"), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), table.Total)
	assert.Empty(t, table.Entries)

	// No output at all is not an error either.
	table, err = StreamRoutes(strings.NewReader(""), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), table.Total)

	// A non-object payload is an error, because it means the command failed.
	_, err = StreamRoutes(strings.NewReader(`["nope"]`), 0)
	require.Error(t, err)
}

func TestParseEVPNVNIs(t *testing.T) {
	vnis, err := ParseEVPNVNIs(readFixture(t, "show_evpn_vni.json"))
	require.NoError(t, err)
	require.Len(t, vnis, 3)

	l2 := vnis[0]
	assert.Equal(t, int64(4001), l2.VNI)
	assert.Equal(t, "L2", l2.Type)
	assert.Equal(t, "cluster", l2.VRF)
	assert.Equal(t, "vni4001", l2.VxlanInterface)
	assert.Equal(t, int64(12), l2.NumMacs)
	assert.Equal(t, int64(2), l2.NumRemoteVteps)
	assert.Equal(t, []string{"192.0.2.31", "192.0.2.32"}, l2.RemoteVteps)

	// An L3 VNI uses different key spellings for the same facts.
	l3 := vnis[1]
	assert.Equal(t, int64(5000), l3.VNI)
	assert.Equal(t, "L3", l3.Type)
	assert.Equal(t, "cluster", l3.VRF)
	assert.Equal(t, "vni5000", l3.VxlanInterface)
	assert.Equal(t, "vlan5000", l3.SVIInterface)
	assert.Equal(t, "aa:bb:cc:00:00:30", l3.RouterMAC)
	assert.Equal(t, "Up", l3.State)

	// A tenant L3 VNI that is down is the finding this resource exists for.
	assert.Equal(t, "t-blue", vnis[2].VRF)
	assert.Equal(t, "Down", vnis[2].State)
}

func TestParseShowVRF(t *testing.T) {
	vrfs := ParseShowVRF(string(readFixture(t, "show_vrf.txt")))
	require.Len(t, vrfs, 4)
	assert.Equal(t, "cluster", vrfs[0].Name)
	assert.Equal(t, int64(5), vrfs[0].ID)
	assert.Equal(t, int64(1005), vrfs[0].TableID)
	assert.Equal(t, "vr.mgmt", vrfs[3].Name)

	// A line without a table is still a VRF.
	one := ParseShowVRF("vrf local-only id 9\nnot a vrf line\n")
	require.Len(t, one, 1)
	assert.Equal(t, "local-only", one[0].Name)
	assert.Equal(t, int64(0), one[0].TableID)
}

func TestParseIPLinkVRF(t *testing.T) {
	vrfs, err := ParseIPLinkVRF(readFixture(t, "ip_link_vrf.json"))
	require.NoError(t, err)
	require.Len(t, vrfs, 3)

	assert.Equal(t, "cluster", vrfs[0].Name)
	assert.Equal(t, int64(5), vrfs[0].Ifindex)
	assert.Equal(t, int64(1005), vrfs[0].TableID)
	assert.Equal(t, int64(65575), vrfs[0].MTU)
	assert.True(t, vrfs[0].Up)

	assert.Equal(t, "t-blue", vrfs[2].Name)
	assert.False(t, vrfs[2].Up)
}

func TestParseRtTablesAndRules(t *testing.T) {
	names := ParseRtTables(string(readFixture(t, "rt_tables")))
	assert.Equal(t, "main", names[254])
	assert.Equal(t, "cluster", names[1005])
	assert.Equal(t, "t-blue", names[1007])
	// The comment lines must not become table names.
	assert.Len(t, names, 7)

	rules, err := ParseIPRules(readFixture(t, "ip_rule.json"), names)
	require.NoError(t, err)
	require.Len(t, rules, 6)

	assert.Equal(t, int64(0), rules[0].Priority)
	assert.Equal(t, "local", rules[0].Table)
	assert.Equal(t, int64(255), rules[0].TableID)

	// The l3mdev rule is what sends VRF traffic to the VRF table.
	assert.True(t, rules[1].L3mdev)
	assert.Equal(t, int64(1000), rules[1].Priority)

	// A rule that sends one VRF's source prefix to another VRF's table is a
	// leak between tenants, so the table name has to resolve.
	assert.Equal(t, "10.100.0.0/16", rules[2].Source)
	assert.Equal(t, "vr.mgmt", rules[2].Table)
	assert.Equal(t, int64(1006), rules[2].TableID)

	assert.Equal(t, "hbn", rules[3].InputIf)
	assert.Equal(t, "cluster", rules[3].Table)

	assert.Equal(t, "unreachable", rules[5].Action)
	assert.Equal(t, int64(-1), rules[5].SuppressPrefixLength)
}

func TestMergeVRFs(t *testing.T) {
	zebra := ParseShowVRF(string(readFixture(t, "show_vrf.txt")))
	kernel, err := ParseIPLinkVRF(readFixture(t, "ip_link_vrf.json"))
	require.NoError(t, err)
	names := ParseRtTables(string(readFixture(t, "rt_tables")))

	merged := MergeVRFs(zebra, kernel, names)
	require.Len(t, merged, 4)

	byName := map[string]VRFState{}
	for _, v := range merged {
		byName[v.Name] = v
	}

	cluster := byName["cluster"]
	assert.True(t, cluster.InFRR)
	assert.True(t, cluster.InKernel)
	assert.Equal(t, int64(5), cluster.ID)
	assert.Equal(t, int64(1005), cluster.TableID)
	assert.Equal(t, "cluster", cluster.TableName)
	assert.True(t, cluster.Up)

	// t-green is configured in FRR but has no device on the asset, which the
	// merge has to show rather than hide.
	green := byName["t-green"]
	assert.True(t, green.InFRR)
	assert.False(t, green.InKernel)
	assert.Equal(t, int64(1008), green.TableID)
	assert.Equal(t, "", green.TableName)

	blue := byName["t-blue"]
	assert.True(t, blue.InKernel)
	assert.False(t, blue.Up)
}

// TestEnrichBGPPeers_UsesSummaryKey covers the address family spellings that
// differ between FRR versions. The key FRR wrote in the summary is the key
// its neighbor detail uses, so enrichment must not rebuild it.
func TestEnrichBGPPeers_UsesSummaryKey(t *testing.T) {
	summary := []byte(`{"ipv4LabeledUnicast":{"as":65100,"peers":{
		"swp1":{"remoteAs":65000,"state":"Established","pfxRcd":3,"pfxSnt":1}}}}`)
	peers, err := ParseBGPSummary("", summary)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	assert.Equal(t, "ipv4", peers[0].AFI)
	assert.Equal(t, "labeled-unicast", peers[0].SAFI)
	assert.Equal(t, "ipv4LabeledUnicast", peers[0].SummaryKey)

	detail := []byte(`{"swp1":{"addressFamilyInfo":{"ipv4LabeledUnicast":{
		"acceptedPrefixCounter":3,"routeMapForIncomingAdvertisements":"rm_in"}}}}`)
	require.NoError(t, EnrichBGPPeers(peers, detail))
	assert.Equal(t, "rm_in", peers[0].RouteMapIn)
	assert.Equal(t, int64(3), peers[0].PrefixesAccepted)
}

func TestSummaryKeyFor(t *testing.T) {
	assert.Equal(t, "ipv4Unicast", summaryKeyFor("ipv4", "unicast"))
	assert.Equal(t, "ipv6Multicast", summaryKeyFor("ipv6", "multicast"))
	assert.Equal(t, "l2VpnEvpn", summaryKeyFor("l2vpn", "evpn"))
	// A compound SAFI keeps its word boundaries, the way FRR writes the key.
	assert.Equal(t, "ipv4LabeledUnicast", summaryKeyFor("ipv4", "labeled-unicast"))
	assert.Equal(t, "l2VpnVpls", summaryKeyFor("l2vpn", "vpls"))
}

// TestRefused covers the answer vtysh gives for a VRF that a daemon does
// not serve. It exits zero, so only the text says the query was refused.
func TestRefused(t *testing.T) {
	assert.True(t, Refused([]byte("% VRF t-blue not found\n")))
	assert.True(t, Refused([]byte("\n  % Unknown command: show bgp vrf x summary json\n")))
	assert.False(t, Refused([]byte(`{"ipv4Unicast":{}}`)))
	assert.False(t, Refused([]byte("")))
}

// TestStreamRoutes_BrokenEntryStopsCleanly covers a value that cannot be
// decoded. The decoder must not carry on from the middle of the table,
// because everything after that point would be read as noise.
func TestStreamRoutes_BrokenEntryStopsCleanly(t *testing.T) {
	// The second prefix holds an entry whose type does not match, so it is
	// skipped, and the third prefix is still read.
	src := `{"10.0.0.0/8":[{"prefix":"10.0.0.0/8","protocol":"bgp"}],` +
		`"10.1.0.0/16":["not an object"],` +
		`"10.2.0.0/16":[{"prefix":"10.2.0.0/16","protocol":"static"}]}`
	table, err := StreamRoutes(strings.NewReader(src), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(3), table.Total)
	require.Len(t, table.Entries, 2)
	assert.Equal(t, "10.0.0.0/8", table.Entries[0].Prefix)
	assert.Equal(t, "10.2.0.0/16", table.Entries[1].Prefix)

	// A truncated document is an error rather than a partial answer.
	_, err = StreamRoutes(strings.NewReader(`{"10.0.0.0/8":[{"prefix":`), 0)
	require.Error(t, err)
}

// TestStreamRoutes_TruncatedOnDroppedEntries pins that a result which does
// not hold everything FRR reported says so. A policy that reads a partial
// table as a complete one would pass on missing data.
func TestStreamRoutes_TruncatedOnDroppedEntries(t *testing.T) {
	// The last prefix carries three entries and only one fits the limit.
	src := `{"10.0.0.0/8":[{"prefix":"10.0.0.0/8","protocol":"bgp"}],` +
		`"10.1.0.0/16":[{"prefix":"10.1.0.0/16","protocol":"bgp"},` +
		`{"prefix":"10.1.0.0/16","protocol":"static"},` +
		`{"prefix":"10.1.0.0/16","protocol":"kernel"}]}`
	table, err := StreamRoutes(strings.NewReader(src), 2)
	require.NoError(t, err)
	assert.Len(t, table.Entries, 2)
	assert.True(t, table.Truncated)
	assert.Equal(t, int64(2), table.Total)

	// A prefix that cannot be read is also missing data.
	broken := `{"10.0.0.0/8":[{"prefix":"10.0.0.0/8"}],"10.1.0.0/16":["nope"]}`
	table, err = StreamRoutes(strings.NewReader(broken), 0)
	require.NoError(t, err)
	assert.Len(t, table.Entries, 1)
	assert.True(t, table.Truncated)

	// A complete answer still reports false.
	whole := `{"10.0.0.0/8":[{"prefix":"10.0.0.0/8"}]}`
	table, err = StreamRoutes(strings.NewReader(whole), 0)
	require.NoError(t, err)
	assert.False(t, table.Truncated)
}
