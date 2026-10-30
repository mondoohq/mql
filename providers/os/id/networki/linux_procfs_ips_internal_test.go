// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Captured from an amazonlinux:2027 container, which ships no iproute2 and so
// takes the sysfs detector. `ip addr` on the same namespace reports exactly two
// addresses: 127.0.0.1/8 on lo and 172.17.0.2/16 on eth0.
const fibTrieContainer = `Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
`

// Captured from the same container, whose only route is a default via the
// docker bridge plus the on-link /16.
const routeContainer = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010011AC	0003	0	0	0	00000000	0	0	0
eth0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

// Captured from the host network namespace of the Docker Desktop VM: four
// interfaces, a loopback route the container above does not have, and a /32
// host route on a point-to-point interface.
const routeHostNS = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
lo	0000007F	00000000	0001	0	0	0	000000FF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
eth0	0041A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
services1	0741A8C0	00000000	0005	0	0	0	FFFFFFFF	0	0	0
`

// Captured from the same host namespace: a global and a link-local address on
// eth0, loopback, and link-locals on the bridge and the point-to-point device.
const ifInet6HostNS = `fdc4f303932400000000000000000006 0f 80 00 82 services1
fe80000000000000c04433fffe64577c 04 40 20 80     eth0
fdc4f303932400000000000000000003 04 40 00 82     eth0
00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000c505bfffe979522 10 40 20 80  docker0
fe80000000000000b436bbfffe27ec74 0f 40 20 80 services1
`

func TestParseProcNetFibTrieLocalIPv4(t *testing.T) {
	addrs := parseProcNetFibTrieLocalIPv4(strings.NewReader(fibTrieContainer))

	got := make([]string, 0, len(addrs))
	for _, a := range addrs {
		got = append(got, a.String())
	}

	// Exactly the two addresses `ip addr` shows. 127.0.0.0 carries a
	// "/8 host LOCAL" of its own -- the reservation for the loopback device,
	// not an address -- and taking every LOCAL line would invent it. The
	// network address 172.17.0.0 and the broadcast 172.17.255.255 are not
	// LOCAL at all.
	assert.Equal(t, []string{"127.0.0.1", "172.17.0.2"}, got)
}

func TestParseProcNetFibTrieSkipsAliasOfAnotherLeaf(t *testing.T) {
	// The alias lines belong to the leaf above them. A leaf whose own aliases
	// are not /32 LOCAL must not pick up the LOCAL of a later leaf.
	const trie = `Main:
     +-- 10.0.0.0/8 2 0 2
        |-- 10.0.0.0
           /8 link UNICAST
        |-- 10.1.2.3
           /32 host LOCAL
`
	addrs := parseProcNetFibTrieLocalIPv4(strings.NewReader(trie))
	require.Len(t, addrs, 1)
	assert.Equal(t, "10.1.2.3", addrs[0].String())
}

func TestParseProcNetFibTrieEmpty(t *testing.T) {
	assert.Empty(t, parseProcNetFibTrieLocalIPv4(strings.NewReader("")))
}

func TestParseProcNetIfInet6(t *testing.T) {
	byIface := parseProcNetIfInet6(strings.NewReader(ifInet6HostNS))

	require.Contains(t, byIface, "eth0")
	eth0 := make([]string, 0, len(byIface["eth0"]))
	for _, ip := range byIface["eth0"] {
		eth0 = append(eth0, ip.CIDR)
	}
	// 40 hex is a /64 prefix, not /40 -- the field is hexadecimal.
	assert.ElementsMatch(t,
		[]string{"fe80::c044:33ff:fe64:577c/64", "fdc4:f303:9324::3/64"},
		eth0)

	require.Contains(t, byIface, "lo")
	require.Len(t, byIface["lo"], 1)
	assert.Equal(t, "::1/128", byIface["lo"][0].CIDR)

	// 80 hex is 128, so the loopback subnet is the address itself.
	assert.Equal(t, "::1/128", byIface["lo"][0].Subnet)

	assert.Len(t, byIface["services1"], 2)
	assert.Len(t, byIface["docker0"], 1)
}

func TestParseProcNetIfInet6RejectsMalformedLines(t *testing.T) {
	const bad = `notlongenough 04 40 20 80 eth0
fe80000000000000c04433fffe64577c 04 zz 20 80 eth1
fe80000000000000c04433fffe64577c 04 40 20 80
fe80000000000000c04433fffe64577c 04 40 20 80 eth3
`
	byIface := parseProcNetIfInet6(strings.NewReader(bad))

	// A short address, an unparsable prefix length and a missing device name
	// each drop only their own line.
	assert.NotContains(t, byIface, "eth0")
	assert.NotContains(t, byIface, "eth1")
	require.Contains(t, byIface, "eth3")
	assert.Equal(t, "fe80::c044:33ff:fe64:577c/64", byIface["eth3"][0].CIDR)
}

func TestReadProcNetRoutesParsesLittleEndianHex(t *testing.T) {
	routes := parseProcNetRoutes(strings.NewReader(routeContainer))

	// 000011AC little-endian is 172.17.0.0 and 0000FFFF is 255.255.0.0.
	require.Len(t, routes.connected, 1)
	assert.Equal(t, "eth0", routes.connected[0].iface)
	assert.Equal(t, "172.17.0.0/16", routes.connected[0].ipNet.String())

	// The default route contributes the gateway, not an on-link network.
	assert.Equal(t, "172.17.0.1", routes.gatewayFor["eth0"])
}

func TestAttributeIPv4(t *testing.T) {
	routes := parseProcNetRoutes(strings.NewReader(routeHostNS))

	tests := []struct {
		addr      string
		iface     string
		prefixLen int
		ok        bool
	}{
		{"172.17.0.1", "docker0", 16, true},
		{"192.168.65.3", "eth0", 24, true},
		{"192.168.65.6", "eth0", 24, true},
		// The /32 host route on the point-to-point interface is more specific
		// than eth0's /24, so it wins for the one address it covers.
		{"192.168.65.7", "services1", 32, true},
		// This namespace does have a loopback route, so 127.0.0.1 resolves
		// through it rather than through the fallback.
		{"127.0.0.1", "lo", 8, true},
		// Nothing on-link covers a public address, and guessing an interface
		// for it would attribute the whole internet to one NIC.
		{"8.8.8.8", "", 0, false},
	}

	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			iface, prefixLen, ok := attributeIPv4(net.ParseIP(test.addr), routes.connected)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.iface, iface)
			assert.Equal(t, test.prefixLen, prefixLen)
		})
	}
}

func TestAttributeIPv4LoopbackWithoutARoute(t *testing.T) {
	// The amazonlinux:2027 container has no loopback route at all, so without
	// the reservation fallback 127.0.0.1 would go unattributed.
	routes := parseProcNetRoutes(strings.NewReader(routeContainer))

	iface, prefixLen, ok := attributeIPv4(net.ParseIP("127.0.0.1"), routes.connected)
	assert.True(t, ok)
	assert.Equal(t, "lo", iface)
	assert.Equal(t, 8, prefixLen)
}

func TestAttributeIPv4IgnoresDefaultRoute(t *testing.T) {
	// A default route covers every address there is. Treating it as on-link
	// would attribute any address to its interface with a /0 prefix.
	routes := parseProcNetRoutes(strings.NewReader(routeContainer))
	for _, route := range routes.connected {
		ones, _ := route.ipNet.Mask.Size()
		assert.NotZero(t, ones, "a /0 route was kept as on-link")
	}

	_, _, ok := attributeIPv4(net.ParseIP("8.8.8.8"), routes.connected)
	assert.False(t, ok)
}

// Captured from a container on a docker network with IPv6 enabled. The last
// line is the unreachable ::/0 the kernel keeps on loopback.
const ipv6RouteHostNS = `20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001     eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000100000000000000000001 00000400 00000001 00000000 00000003     eth0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000005 00000000 80200001       lo
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 0000000d 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`

func TestParseProcNetIPv6Gateways(t *testing.T) {
	gateways := parseProcNetIPv6Gateways(strings.NewReader(ipv6RouteHostNS))

	assert.Equal(t, "2001:db8:1::1", gateways["eth0"])

	// The kernel installs an unreachable ::/0 on loopback for a host with no
	// IPv6 connectivity. It has no next hop, and taking it would report "::"
	// as the gateway of every IPv6 address.
	assert.NotContains(t, gateways, "lo")
}

func TestParseProcNetIPv6GatewaysWithoutADefaultRoute(t *testing.T) {
	// On-link and multicast routes are not default routes, so a host with no
	// IPv6 default route gets no gateway rather than one invented from them.
	const onlinkOnly = `20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001     eth0
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 0000000d 00000000 00000001     eth0
`
	assert.Empty(t, parseProcNetIPv6Gateways(strings.NewReader(onlinkOnly)))
}

func TestHexLEToIPv4(t *testing.T) {
	tests := []struct {
		hex      string
		expected string
		ok       bool
	}{
		{"00000000", "0.0.0.0", true},
		{"000011AC", "172.17.0.0", true},
		{"010011AC", "172.17.0.1", true},
		{"0000FFFF", "255.255.0.0", true},
		{"0041A8C0", "192.168.65.0", true},
		{"zzzz", "", false},
		{"", "", false},
	}

	for _, test := range tests {
		t.Run(test.hex, func(t *testing.T) {
			ip, ok := hexLEToIPv4(test.hex)
			require.Equal(t, test.ok, ok)
			if test.ok {
				assert.Equal(t, test.expected, ip.String())
			}
		})
	}
}

func TestHexToIPv6Addr(t *testing.T) {
	ip, ok := hexToIPv6Addr("00000000000000000000000000000001")
	require.True(t, ok)
	assert.Equal(t, "::1", ip.String())

	ip, ok = hexToIPv6Addr("fe80000000000000c04433fffe64577c")
	require.True(t, ok)
	assert.Equal(t, "fe80::c044:33ff:fe64:577c", ip.String())

	_, ok = hexToIPv6Addr("tooshort")
	assert.False(t, ok)

	_, ok = hexToIPv6Addr("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	assert.False(t, ok)
}

func TestInterfacesHaveNoIPs(t *testing.T) {
	assert.True(t, interfacesHaveNoIPs([]Interface{{Name: "eth0"}, {Name: "lo"}}))
	assert.True(t, interfacesHaveNoIPs(nil))

	withIP := Interface{Name: "eth0"}
	withIP.AddOrUpdateIP(NewIPv4WithPrefixLength("10.0.0.1", 24))
	assert.False(t, interfacesHaveNoIPs([]Interface{{Name: "lo"}, withIP}))
}
