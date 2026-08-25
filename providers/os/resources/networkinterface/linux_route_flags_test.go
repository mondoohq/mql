// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Linux and BSD agree only up to RTF_HOST. Everything above it means something
// different on each, so decoding a Linux route with the BSD table renames most
// of the flags and invents a REJECT that is not there.
func TestLinuxAndBsdRouteFlagsDiverge(t *testing.T) {
	tests := []struct {
		name  string
		flags int64
		linux []string
		bsd   []string
	}{
		{"up", 0x0001, []string{"UP"}, []string{"UP"}},
		{"up+gateway", 0x0003, []string{"GATEWAY", "UP"}, []string{"GATEWAY", "UP"}},
		{"host", 0x0004, []string{"HOST"}, []string{"HOST"}},
		// from here the two tables disagree
		{"reinstate is not reject", 0x0008, []string{"REINSTATE"}, []string{"REJECT"}},
		{"mtu is not done", 0x0040, []string{"MTU"}, []string{"DONE"}},
		{"window is not mask", 0x0080, []string{"WINDOW"}, []string{"MASK"}},
		{"irtt is not cloning", 0x0100, []string{"IRTT"}, []string{"CLONING"}},
		{"reject is not xresolve", 0x0200, []string{"REJECT"}, []string{"XRESOLVE"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.linux, parseLinuxRouteFlags(tc.flags))
			assert.Equal(t, tc.bsd, parseBSDRouteFlags(tc.flags))
		})
	}
}

// Captured from /proc/net/ipv6_route on Arch Linux 2026.08 in EC2: 0x00200200
// is RTF_NONEXTHOP|RTF_REJECT, the unreachable ::/0 the kernel installs on a
// host with no IPv6 default route.
func TestLinuxIPv6RouteFlags(t *testing.T) {
	flags := parseLinuxIPv6RouteFlags(0x00200200)
	assert.Equal(t, []string{"NONEXTHOP", "REJECT"}, flags)
	assert.True(t, routeFlagsRejected(flags))

	// a real router-advertised default carries no REJECT
	ra := parseLinuxIPv6RouteFlags(0x00040003)
	assert.Equal(t, []string{"ADDRCONF", "GATEWAY", "UP"}, ra)
	assert.False(t, routeFlagsRejected(ra))

	// the IPv6 table must still carry the IPv4 bits it shares
	assert.Equal(t, []string{"UP"}, parseLinuxIPv6RouteFlags(0x0001))

	// the top bit must not be lost to sign extension
	assert.Contains(t, parseLinuxIPv6RouteFlags(0x80000000), "LOCAL")
}

// The whole point: an unreachable ::/0 must not be reported as a default route.
func TestParseLinuxIPv6RoutesSkipsRejectRoutes(t *testing.T) {
	// dest prefixlen src srcprefixlen nexthop metric ref use flags device
	const procIPv6Route = `fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`
	l := &linuxRouteDetector{}
	routes, err := l.parseLinuxIPv6RoutesFromProc(procIPv6Route)
	require.NoError(t, err)

	require.Len(t, routes, 1, "the two unreachable ::/0 entries must not be reported")
	assert.Equal(t, "fe80::/64", routes[0].Destination)
	assert.Equal(t, "eth0", routes[0].Interface)
	assert.Equal(t, []string{"UP"}, routes[0].Flags, "flags must come from the flags column, not be left empty")
}

// A genuine IPv6 default route must survive.
func TestParseLinuxIPv6RoutesKeepsRealDefault(t *testing.T) {
	const procIPv6Route = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00040003     eth0
`
	l := &linuxRouteDetector{}
	routes, err := l.parseLinuxIPv6RoutesFromProc(procIPv6Route)
	require.NoError(t, err)

	require.Len(t, routes, 1)
	assert.Equal(t, "::/0", routes[0].Destination)
	assert.Equal(t, "fe80::1", routes[0].Gateway)
	assert.Equal(t, []string{"ADDRCONF", "GATEWAY", "UP"}, routes[0].Flags)
}

// /proc/net/route is the primary IPv4 source, and it reports unreachable and
// prohibit entries with RTF_REJECT just as the IPv6 table does. Without the
// same guard the two sources disagree: `ip route` skips them by type while
// /proc reports them as ordinary routes.
//
// Fixture captured from a Linux host carrying all three discard types:
//
//	ip route add unreachable 10.99.0.0/16
//	ip route add blackhole   10.98.0.0/16
//	ip route add prohibit    10.97.0.0/16
func TestParseLinuxRoutesFromProcSkipsRejectRoutes(t *testing.T) {
	const procRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010011AC	0003	0	0	0	00000000	0	0	0
*	0000610A	00000000	0201	0	0	0	0000FFFF	0	0	0
*	0000620A	00000000	0001	0	0	0	0000FFFF	0	0	0
*	0000630A	00000000	0201	0	0	0	0000FFFF	0	0	0
eth0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`
	l := &linuxRouteDetector{}
	routes, err := l.parseLinuxRoutesFromProc(procRoute)
	require.NoError(t, err)

	var dests []string
	for _, r := range routes {
		dests = append(dests, r.Destination)
	}

	assert.NotContains(t, dests, "10.99.0.0/16", "unreachable route must not be reported")
	assert.NotContains(t, dests, "10.97.0.0/16", "prohibit route must not be reported")

	assert.Contains(t, dests, "0.0.0.0/0", "the real default route must survive")
	assert.Contains(t, dests, "172.17.0.0/16", "the real link route must survive")

	// The kernel's fib_flag_trans maps only RTN_UNREACHABLE and RTN_PROHIBIT to
	// RTF_REJECT, so a blackhole route reaches /proc with flags 0001 and is
	// indistinguishable from a live one here. `ip route show table all` filters
	// it by type instead.
	assert.Contains(t, dests, "10.98.0.0/16",
		"blackhole carries no REJECT bit in /proc/net/route; only the JSON path can filter it")
}

// `ip route show table all` reports the discard entries with a type. The struct
// has always parsed the field; nothing read it.
func TestIpRouteJSONSkipsDiscardRoutes(t *testing.T) {
	const output = `[
  {"dst":"default","gateway":"172.31.0.1","dev":"eth0","flags":[]},
  {"type":"unreachable","dst":"default","dev":"lo","flags":[]},
  {"type":"blackhole","dst":"10.0.0.0/8","dev":"lo","flags":[]},
  {"type":"prohibit","dst":"192.168.5.0/24","dev":"lo","flags":[]},
  {"dst":"172.31.0.0/20","dev":"eth0","prefsrc":"172.31.1.5","flags":[]}
]`
	l := &linuxRouteDetector{}
	routes, err := l.parseIpRouteJSON(output)
	require.NoError(t, err)

	require.Len(t, routes, 2)
	assert.Equal(t, "0.0.0.0", routes[0].Destination)
	assert.Equal(t, "172.31.0.1", routes[0].Gateway)
	assert.Equal(t, "172.31.0.0/20", routes[1].Destination)
}
