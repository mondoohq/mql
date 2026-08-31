// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func staticRouteFor(routes []StaticRoute, prefix string) *StaticRoute {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}

func communityListFor(lists []CommunityList, name string) *CommunityList {
	for i := range lists {
		if lists[i].Name == name {
			return &lists[i]
		}
	}
	return nil
}

func routeMapEntryFor(maps []RouteMap, name string, seq int64) *RouteMapEntry {
	for i := range maps {
		if maps[i].Name != name {
			continue
		}
		for j := range maps[i].Entries {
			if maps[i].Entries[j].Sequence == seq {
				return &maps[i].Entries[j]
			}
		}
	}
	return nil
}

func TestStaticRoutes(t *testing.T) {
	cfg := parseFixture(t, "frr-policy.conf")
	routes := cfg.StaticRoutes()
	require.Len(t, routes, 7)

	def := staticRouteFor(routes, "0.0.0.0/0")
	require.NotNil(t, def)
	assert.Equal(t, "ipv4", def.AFI)
	assert.Equal(t, "192.0.2.1", def.Nexthop)
	assert.Equal(t, int64(200), def.Distance)
	assert.Equal(t, "", def.VRF)

	// A route can name its VRF, its table and its tag on one line.
	mgmt := staticRouteFor(routes, "10.50.0.0/16")
	require.NotNil(t, mgmt)
	assert.Equal(t, "vr.mgmt", mgmt.VRF)
	assert.Equal(t, int64(1006), mgmt.Table)
	assert.Equal(t, int64(400), mgmt.Tag)

	iface := staticRouteFor(routes, "172.16.0.0/12")
	require.NotNil(t, iface)
	assert.Equal(t, "eth0", iface.Interface)
	assert.Equal(t, "", iface.Nexthop)

	v6 := staticRouteFor(routes, "2001:db8::/32")
	require.NotNil(t, v6)
	assert.Equal(t, "ipv6", v6.AFI)
	assert.True(t, v6.Blackhole)

	// Null0 is the other spelling of a discard route.
	null := staticRouteFor(routes, "192.168.99.0/24")
	require.NotNil(t, null)
	assert.True(t, null.Blackhole)

	// A route inside a vrf block belongs to that VRF.
	inVrf := staticRouteFor(routes, "10.100.0.0/16")
	require.NotNil(t, inVrf)
	assert.Equal(t, "cluster", inVrf.VRF)
	assert.True(t, inVrf.Blackhole)

	// A next hop resolved in another VRF is how a route leaks between them.
	leak := staticRouteFor(routes, "10.200.0.0/16")
	require.NotNil(t, leak)
	assert.Equal(t, "cluster", leak.VRF)
	assert.Equal(t, "vr.mgmt", leak.NexthopVRF)
	assert.Equal(t, "vr.mgmt", leak.Interface)
}

func TestCommunityLists(t *testing.T) {
	cfg := parseFixture(t, "frr-policy.conf")
	lists := cfg.CommunityLists()
	require.Len(t, lists, 5)

	fabric := communityListFor(lists, "cm-received-fabric")
	require.NotNil(t, fabric)
	assert.Equal(t, "community", fabric.Kind)
	assert.Equal(t, "standard", fabric.Type)
	require.Len(t, fabric.Entries, 2)
	assert.Equal(t, "permit", fabric.Entries[0].Action)
	assert.Equal(t, "65100:200", fabric.Entries[0].Value)
	assert.Equal(t, "65100:201", fabric.Entries[1].Value)

	expanded := communityListFor(lists, "cm-any-tenant")
	require.NotNil(t, expanded)
	assert.Equal(t, "expanded", expanded.Type)
	assert.Equal(t, "deny", expanded.Entries[0].Action)
	assert.Equal(t, "_65[0-9]*_", expanded.Entries[0].Value)

	large := communityListFor(lists, "lcm-tenant")
	require.NotNil(t, large)
	assert.Equal(t, "large-community", large.Kind)
	assert.Equal(t, "65100:1:2", large.Entries[0].Value)

	ext := communityListFor(lists, "ecm-tenant-rt")
	require.NotNil(t, ext)
	assert.Equal(t, "extcommunity", ext.Kind)
	assert.Equal(t, "rt 65100:5000", ext.Entries[0].Value)

	// The legacy `ip community-list` spelling reaches the same resource.
	legacy := communityListFor(lists, "cm-legacy")
	require.NotNil(t, legacy)
	assert.Equal(t, "community", legacy.Kind)
}

func TestAccessLists(t *testing.T) {
	cfg := parseFixture(t, "frr-policy.conf")
	lists := cfg.AccessLists()
	require.Len(t, lists, 2)

	assert.Equal(t, "acl_mgmt", lists[0].Name)
	assert.Equal(t, "ipv4", lists[0].AFI)
	require.Len(t, lists[0].Entries, 2)
	assert.Equal(t, int64(5), lists[0].Entries[0].Seq)
	assert.Equal(t, "10.10.0.0/16", lists[0].Entries[0].Value)
	assert.Equal(t, "deny", lists[0].Entries[1].Action)
	assert.Equal(t, "any", lists[0].Entries[1].Value)

	assert.Equal(t, "acl_mgmt6", lists[1].Name)
	assert.Equal(t, "ipv6", lists[1].AFI)
}

func TestASPathAccessLists(t *testing.T) {
	cfg := parseFixture(t, "frr-policy.conf")
	lists := cfg.ASPathAccessLists()
	require.Len(t, lists, 1)
	assert.Equal(t, "ap-transit", lists[0].Name)
	require.Len(t, lists[0].Entries, 2)
	assert.Equal(t, "permit", lists[0].Entries[0].Action)
	assert.Equal(t, "^65000_", lists[0].Entries[0].Value)
	assert.Equal(t, "deny", lists[0].Entries[1].Action)
	assert.Equal(t, ".*", lists[0].Entries[1].Value)
}

// TestRouteMapClauses covers the statements that enforce policy. A policy
// asks which list a clause names, not what the line looked like.
func TestRouteMapClauses(t *testing.T) {
	cfg := parseFixture(t, "frr-policy.conf")
	maps := cfg.RouteMaps()

	first := routeMapEntryFor(maps, "rm_tenant_in", 10)
	require.NotNil(t, first)
	c := first.Clauses
	assert.Equal(t, []string{"pl_export_base"}, c.MatchPrefixLists)
	assert.Equal(t, []string{"cm-received-fabric"}, c.MatchCommunityLists)
	assert.Equal(t, "cluster", c.MatchSourceVRF)
	assert.Equal(t, "203.0.113.5", c.MatchPeer)
	assert.Equal(t, int64(50), c.SetLocalPreference)
	assert.Equal(t, []string{"65100:300"}, c.SetCommunities)
	assert.True(t, c.SetCommunityAdditive)
	assert.Equal(t, "+10", c.SetMetric)
	assert.Equal(t, "next", first.OnMatch)
	// The raw statements stay available.
	assert.Contains(t, first.Match, "ip address prefix-list pl_export_base")

	second := routeMapEntryFor(maps, "rm_tenant_in", 20)
	require.NotNil(t, second)
	c = second.Clauses
	assert.Equal(t, []string{"pl_export_base6"}, c.MatchPrefixLists)
	assert.Equal(t, []string{"lcm-tenant"}, c.MatchLargeCommunities)
	assert.Equal(t, []string{"ecm-tenant-rt"}, c.MatchExtCommunities)
	assert.Equal(t, []string{"ap-transit"}, c.MatchAsPathLists)
	assert.Equal(t, "2", c.MatchEvpnRouteType)
	assert.Equal(t, int64(4001), c.MatchEvpnVNI)
	assert.Equal(t, int64(400), c.MatchTag)
	assert.Equal(t, "cm-received-fabric", c.SetCommunityDelete)
	assert.Equal(t, []string{"65100", "65100"}, c.SetAsPathPrepend)
	assert.Equal(t, "2001:db8::1", c.SetNextHop)
	assert.Equal(t, []string{"65100:1:3"}, c.SetLargeCommunities)
	assert.Equal(t, []string{"rt 65100:5010"}, c.SetExtCommunities)
	assert.Equal(t, int64(100), c.SetWeight)
	assert.Equal(t, "igp", c.SetOrigin)
	assert.Equal(t, int64(401), c.SetTag)
	assert.Equal(t, int64(20), c.SetDistance)
	assert.True(t, c.SetAtomicAggregate)

	// An access list match is not a prefix list match.
	third := routeMapEntryFor(maps, "rm_tenant_in", 65535)
	require.NotNil(t, third)
	assert.Equal(t, []string{"acl_mgmt"}, third.Clauses.MatchAccessLists)
	assert.Empty(t, third.Clauses.MatchPrefixLists)

	// An unset number stays -1, so a configured zero is a different answer.
	assert.Equal(t, int64(-1), third.Clauses.SetLocalPreference)
	assert.Equal(t, int64(-1), third.Clauses.MatchEvpnVNI)

	// The VPN next hop spelling names a next hop too, and `set community
	// none` is not a community value.
	cluster := routeMapEntryFor(maps, "rm_cluster_import", 1)
	require.NotNil(t, cluster)
	assert.Equal(t, "0.0.0.0", cluster.Clauses.SetNextHop)
	assert.True(t, cluster.Clauses.SetCommunityNone)
	assert.Empty(t, cluster.Clauses.SetCommunities)
	assert.Equal(t, "rm_tenant_in", cluster.Call)
}

// TestRouteMapClauses_EVPNFixture keeps the earlier fixtures readable through
// the new fields.
func TestRouteMapClauses_EVPNFixture(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")
	maps := cfg.RouteMaps()

	tag := routeMapEntryFor(maps, "TAG-FABRIC-IN", 10)
	require.NotNil(t, tag)
	assert.Equal(t, []string{"65100:200"}, tag.Clauses.SetCommunities)
	assert.True(t, tag.Clauses.SetCommunityAdditive)
	assert.Equal(t, int64(100), tag.Clauses.SetLocalPreference)

	deny := routeMapEntryFor(maps, "DENY-TAG-FABRIC-OUT", 10)
	require.NotNil(t, deny)
	assert.Equal(t, "deny", deny.Action)
	assert.Equal(t, []string{"cm-received-fabric"}, deny.Clauses.MatchCommunityLists)
}

// TestStaticRoutes_ColorArgument pins that the numeric argument of `color`
// is not read as the administrative distance.
func TestStaticRoutes_ColorArgument(t *testing.T) {
	src := `hostname x
ip route 10.0.0.0/8 192.0.2.1 color 100
ip route 10.1.0.0/16 192.0.2.1 color 100 40
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	routes := cfg.StaticRoutes()
	require.Len(t, routes, 2)

	assert.Equal(t, "192.0.2.1", routes[0].Nexthop)
	assert.Equal(t, int64(0), routes[0].Distance)

	// A distance after the color is still read.
	assert.Equal(t, int64(40), routes[1].Distance)
}

// TestStaticRoutes_DiscardDispositions pins that a blackhole and a reject
// route for the same prefix stay two routes. They share an empty target, so
// only the disposition tells them apart.
func TestStaticRoutes_DiscardDispositions(t *testing.T) {
	src := `hostname x
ip route 10.0.0.0/8 blackhole
ip route 10.0.0.0/8 reject
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	routes := cfg.StaticRoutes()
	require.Len(t, routes, 2)
	assert.True(t, routes[0].Blackhole)
	assert.False(t, routes[0].Reject)
	assert.True(t, routes[1].Reject)
	assert.False(t, routes[1].Blackhole)
}

// TestCommunityLists_SameNameDifferentType pins that a standard and an
// expanded list of the same name stay two lists. One matches values, the
// other matches a regular expression.
func TestCommunityLists_SameNameDifferentType(t *testing.T) {
	src := `hostname x
bgp community-list standard FOO permit 65000:1
bgp community-list expanded FOO permit ^65000:
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	lists := cfg.CommunityLists()
	require.Len(t, lists, 2)

	assert.Equal(t, "standard", lists[0].Type)
	assert.Equal(t, "65000:1", lists[0].Entries[0].Value)
	assert.Equal(t, "expanded", lists[1].Type)
	assert.Equal(t, "^65000:", lists[1].Entries[0].Value)
}
