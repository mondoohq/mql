// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRouteMaps_ClausesGrouped(t *testing.T) {
	cfg := `!
route-map IMPORT-FILTER permit 10
   description accept customer prefixes
   match ip address prefix-list CUSTOMER-PREFIXES
   match as-path AS-CUSTOMERS
   set local-preference 200
!
route-map IMPORT-FILTER deny 20
!
route-map EXPORT-FILTER permit 10
   match ip address prefix-list OUR-PREFIXES
   set community 65001:100
!
`
	maps := ParseRouteMaps(cfg)
	require.Len(t, maps, 2)

	byName := map[string]RouteMap{}
	for _, m := range maps {
		byName[m.Name] = m
	}

	imp := byName["IMPORT-FILTER"]
	require.Len(t, imp.Entries, 2)

	e10 := imp.Entries[0]
	assert.Equal(t, "permit", e10.Action)
	assert.Equal(t, 10, e10.SequenceNumber)
	assert.Equal(t, "accept customer prefixes", e10.Description)
	assert.Equal(t, []string{"ip address prefix-list CUSTOMER-PREFIXES", "as-path AS-CUSTOMERS"}, e10.Match)
	assert.Equal(t, []string{"local-preference 200"}, e10.Set)
	assert.Equal(t, []string{"CUSTOMER-PREFIXES"}, e10.MatchPrefixLists)

	// The trailing deny clause is what makes the map default-deny.
	e20 := imp.Entries[1]
	assert.Equal(t, "deny", e20.Action)
	assert.Empty(t, e20.Match)

	assert.Len(t, byName["EXPORT-FILTER"].Entries, 1)
}

func TestParseRouteMaps_ClausesSortedBySequence(t *testing.T) {
	cfg := `route-map M permit 30
   set metric 30
!
route-map M permit 10
   set metric 10
!
route-map M permit 20
   set metric 20
`
	maps := ParseRouteMaps(cfg)
	require.Len(t, maps, 1)
	require.Len(t, maps[0].Entries, 3)
	assert.Equal(t, 10, maps[0].Entries[0].SequenceNumber)
	assert.Equal(t, 20, maps[0].Entries[1].SequenceNumber)
	assert.Equal(t, 30, maps[0].Entries[2].SequenceNumber)
}

func TestParseRouteMaps_Ipv6PrefixListMatch(t *testing.T) {
	cfg := `route-map V6 permit 10
   match ipv6 address prefix-list V6-ALLOWED
`
	maps := ParseRouteMaps(cfg)
	require.Len(t, maps, 1)
	assert.Equal(t, []string{"V6-ALLOWED"}, maps[0].Entries[0].MatchPrefixLists)
}

func TestParseRouteMaps_MultiplePrefixListsPerMatch(t *testing.T) {
	cfg := `route-map MULTI permit 10
   match ip address prefix-list LIST-A LIST-B LIST-C
!
route-map MULTI permit 20
   match ip address prefix-list ONLY-D
   match ipv6 address prefix-list V6-E V6-F
`
	maps := ParseRouteMaps(cfg)
	require.Len(t, maps, 1)
	require.Len(t, maps[0].Entries, 2)

	assert.Equal(t, []string{"LIST-A", "LIST-B", "LIST-C"}, maps[0].Entries[0].MatchPrefixLists)
	// names accumulate across every match clause in the same route-map entry
	assert.Equal(t, []string{"ONLY-D", "V6-E", "V6-F"}, maps[0].Entries[1].MatchPrefixLists)
}

func TestParseRouteMaps_MatchWithoutPrefixList(t *testing.T) {
	cfg := `route-map NOPL permit 10
   match as-path AS-SET
   match community COMM
`
	maps := ParseRouteMaps(cfg)
	require.Len(t, maps, 1)
	assert.Empty(t, maps[0].Entries[0].MatchPrefixLists)
}

func TestParseRouteMaps_None(t *testing.T) {
	assert.Empty(t, ParseRouteMaps("router bgp 65001\n   router-id 10.0.0.1\n"))
}

func TestParsePrefixLists_FlatForm(t *testing.T) {
	cfg := `!
ip prefix-list CUSTOMER-PREFIXES seq 10 permit 10.0.0.0/8 le 24
ip prefix-list CUSTOMER-PREFIXES seq 20 deny 0.0.0.0/0
ipv6 prefix-list V6-ALLOWED seq 10 permit 2001:db8::/32 le 48
!
`
	lists := ParsePrefixLists(cfg)
	require.Len(t, lists, 2)

	byName := map[string]PrefixList{}
	for _, l := range lists {
		byName[l.Name] = l
	}

	cust := byName["CUSTOMER-PREFIXES"]
	assert.Equal(t, "ipv4", cust.Family)
	require.Len(t, cust.Entries, 2)
	assert.Equal(t, 10, cust.Entries[0].SequenceNumber)
	assert.Equal(t, "permit", cust.Entries[0].Action)
	assert.Equal(t, "10.0.0.0/8", cust.Entries[0].Prefix)
	assert.Equal(t, 24, cust.Entries[0].Le)
	assert.Equal(t, 0, cust.Entries[0].Ge)
	assert.Equal(t, "deny", cust.Entries[1].Action)

	v6 := byName["V6-ALLOWED"]
	assert.Equal(t, "ipv6", v6.Family)
	assert.Equal(t, 48, v6.Entries[0].Le)
}

func TestParsePrefixLists_BlockForm(t *testing.T) {
	cfg := `ip prefix-list BLOCKY
   seq 10 permit 192.168.0.0/16 ge 24 le 32
   seq 20 deny 0.0.0.0/0 le 32
`
	lists := ParsePrefixLists(cfg)
	require.Len(t, lists, 1)
	require.Len(t, lists[0].Entries, 2)
	assert.Equal(t, 24, lists[0].Entries[0].Ge)
	assert.Equal(t, 32, lists[0].Entries[0].Le)
	// `permit 0.0.0.0/0 le 32` would accept every route there is; the
	// qualifiers have to survive so that is visible.
	assert.Equal(t, "deny", lists[0].Entries[1].Action)
	assert.Equal(t, 32, lists[0].Entries[1].Le)
}

func TestParsePrefixLists_NoSequenceNumber(t *testing.T) {
	cfg := `ip prefix-list NOSEQ permit 10.0.0.0/8
`
	lists := ParsePrefixLists(cfg)
	require.Len(t, lists, 1)
	require.Len(t, lists[0].Entries, 1)
	assert.Equal(t, 0, lists[0].Entries[0].SequenceNumber)
	assert.Equal(t, "10.0.0.0/8", lists[0].Entries[0].Prefix)
}

func TestParsePrefixLists_SameNameAcrossFamilies(t *testing.T) {
	// Like access-lists, the two families are separate namespaces.
	cfg := `ip prefix-list SHARED seq 10 permit 10.0.0.0/8
ipv6 prefix-list SHARED seq 10 permit 2001:db8::/32
`
	lists := ParsePrefixLists(cfg)
	require.Len(t, lists, 2)
	families := map[string]bool{}
	for _, l := range lists {
		assert.Equal(t, "SHARED", l.Name)
		families[l.Family] = true
	}
	assert.Len(t, families, 2)
}

func TestParsePrefixLists_None(t *testing.T) {
	assert.Empty(t, ParsePrefixLists("route-map M permit 10\n"))
}

func TestParseBgpConfig_NeighborSecurity(t *testing.T) {
	cfg := `!
router bgp 65001
   router-id 10.0.0.1
   bgp log-neighbor-changes
   neighbor 10.1.1.2 remote-as 65002
   neighbor 10.1.1.2 password 7 042B0F1C
   neighbor 10.1.1.2 ttl maximum-hops 1
   neighbor 10.1.1.2 maximum-routes 12000
   neighbor 10.1.1.2 route-map IMPORT-FILTER in
   neighbor 10.1.1.2 route-map EXPORT-FILTER out
   neighbor 10.0.0.2 remote-as 65001
   neighbor 10.0.0.2 update-source Loopback0
   neighbor 10.1.1.6 remote-as 65003
   neighbor 10.1.1.6 shutdown
!
`
	c := ParseBgpConfig(cfg)
	assert.True(t, c.LogNeighborChanges)
	require.Len(t, c.Neighbors, 3)

	p1 := c.Neighbors[0]
	assert.Equal(t, "default", p1.VRF)
	assert.Equal(t, "10.1.1.2", p1.PeerAddress)
	assert.True(t, p1.PasswordConfigured)
	assert.Equal(t, "7", p1.PasswordEncryptionType)
	assert.Equal(t, 1, p1.TtlMaximumHops)
	assert.Equal(t, 12000, p1.MaximumRoutes)
	assert.Equal(t, "IMPORT-FILTER", p1.InboundRouteMap)
	assert.Equal(t, "EXPORT-FILTER", p1.OutboundRouteMap)
	assert.False(t, p1.Shutdown)

	// An unprotected session: no password, no hop limit, no route cap.
	p2 := c.Neighbors[1]
	assert.Equal(t, "10.0.0.2", p2.PeerAddress)
	assert.False(t, p2.PasswordConfigured)
	assert.Equal(t, 0, p2.TtlMaximumHops)
	assert.Equal(t, 0, p2.MaximumRoutes)
	assert.Equal(t, "Loopback0", p2.UpdateSource)

	assert.True(t, c.Neighbors[2].Shutdown)
}

func TestParseBgpConfig_VrfNeighborsAreScoped(t *testing.T) {
	// A VRF sub-block scopes its neighbors. Falling out of the block must
	// return to the unnamed instance, or a later neighbor is misattributed.
	cfg := `router bgp 65001
   neighbor 10.1.1.2 remote-as 65002
   vrf PROD
      router-id 10.100.0.1
      neighbor 10.100.1.2 remote-as 65099
      neighbor 10.100.1.2 password 0 plaintext
   vrf DEV
      neighbor 10.200.1.2 remote-as 65098
   neighbor 10.1.1.3 remote-as 65004
`
	c := ParseBgpConfig(cfg)
	require.Len(t, c.Neighbors, 4)

	byPeer := map[string]BgpNeighborConfig{}
	for _, n := range c.Neighbors {
		byPeer[n.PeerAddress] = n
	}
	assert.Equal(t, "default", byPeer["10.1.1.2"].VRF)
	assert.Equal(t, "PROD", byPeer["10.100.1.2"].VRF)
	assert.Equal(t, "0", byPeer["10.100.1.2"].PasswordEncryptionType)
	assert.Equal(t, "DEV", byPeer["10.200.1.2"].VRF)
	assert.Equal(t, "default", byPeer["10.1.1.3"].VRF)
}

func TestParseBgpConfig_StopsAtNextTopLevelBlock(t *testing.T) {
	// `neighbor` also appears under other routing protocols; only lines
	// inside the router bgp block are BGP neighbors.
	cfg := `router bgp 65001
   neighbor 10.1.1.2 remote-as 65002
router ospf 1
   neighbor 10.9.9.9
`
	c := ParseBgpConfig(cfg)
	require.Len(t, c.Neighbors, 1)
	assert.Equal(t, "10.1.1.2", c.Neighbors[0].PeerAddress)
}

func TestParseBgpConfig_None(t *testing.T) {
	c := ParseBgpConfig("interface Ethernet1\n   description X\n")
	assert.Empty(t, c.Neighbors)
	assert.False(t, c.LogNeighborChanges)
}

func TestParseBgpConfig_TruncatedNeighborLineDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		c := ParseBgpConfig("router bgp 65001\n   neighbor 10.1.1.2\n   neighbor\n")
		assert.Empty(t, c.Neighbors)
	})
}
