// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// The kernel publishes interface attributes under /sys/class/net but not the
// addresses configured on them, so the sysfs detector cannot answer IPAddresses
// and every interface came back with none wherever iproute2 was absent -- and
// with it network.ipv4, network.ipv6, network.primaryIPv4 and ipAddress. procfs
// carries the addresses on every Linux kernel and is readable over ssh, docker
// and a mounted filesystem alike, which `ip addr` is not.
const (
	procNetRoute     = "/proc/net/route"
	procNetFibTrie   = "/proc/net/fib_trie"
	procNetIfInet6   = "/proc/net/if_inet6"
	procNetIPv6Route = "/proc/net/ipv6_route"
	loopbackName     = "lo"
	loopbackPrefix   = 8
	ipv6HexAddrSize  = 32
)

// connectedRoute is a directly attached IPv4 route: one the kernel installs for
// the subnet of an address configured on an interface. Matching a local address
// against these is what ties it back to the interface carrying it, which
// /proc/net/fib_trie does not record.
type connectedRoute struct {
	iface string
	ipNet *net.IPNet
}

// procNetRoutes is what one read of /proc/net/route yields: the on-link routes
// used to attribute addresses to interfaces, and the default gateway per
// interface.
type procNetRoutes struct {
	connected  []connectedRoute
	gatewayFor map[string]string
}

// getLinuxProcfsIPs reads the IPv4 and IPv6 addresses configured on each
// interface out of procfs.
//
// It runs as an enrichment rather than inside a detector because only one
// detector runs: `ip addr` answers where iproute2 is installed and already
// carries addresses, the sysfs walk answers otherwise and cannot. knownIfaces
// bounds what it may report, so a routing table naming an interface that was
// never discovered cannot add one -- the enrichment fills in interfaces, it
// does not find them.
func (n *neti) getLinuxProcfsIPs(knownIfaces []string) ([]Interface, error) {
	known := map[string]bool{}
	for _, name := range knownIfaces {
		known[baseInterfaceName(name)] = true
	}

	byName := map[string]*Interface{}
	addIP := func(iface string, ip IPAddress) {
		iface = baseInterfaceName(iface)
		if !known[iface] {
			log.Debug().Str("interface", iface).
				Msg("os.network.interface> skipping address for an interface that was not discovered")
			return
		}
		if _, ok := byName[iface]; !ok {
			byName[iface] = &Interface{Name: iface, IPAddresses: []IPAddress{}}
		}
		byName[iface].AddOrUpdateIP(ip)
	}

	routes := n.readProcNetRoutes()
	for _, addr := range n.readProcNetFibTrieLocalIPv4() {
		iface, prefixLen, ok := attributeIPv4(addr, routes.connected)
		if !ok {
			log.Debug().Str("ip", addr.String()).
				Msg("os.network.interface> no on-link route for local address, cannot attribute it")
			continue
		}
		ip := NewIPv4WithPrefixLength(addr.String(), prefixLen)
		ip.Gateway = routes.gatewayFor[iface]
		addIP(iface, ip)
	}

	v6Gateways := n.readProcNetIPv6Gateways()
	for iface, addrs := range n.readProcNetIfInet6() {
		for _, addr := range addrs {
			addr.Gateway = v6Gateways[iface]
			addIP(iface, addr)
		}
	}

	interfaces := make([]Interface, 0, len(byName))
	for _, iface := range byName {
		interfaces = append(interfaces, *iface)
	}

	log.Debug().
		Interface("interfaces", interfaces).
		Str("detector", "procfs.ip_addresses").
		Msg("os.network.interfaces> discovered addresses")

	return interfaces, nil
}

// attributeIPv4 finds the interface a local address sits on, and the prefix
// length it was configured with, by longest-prefix match against the on-link
// routes. The kernel installs one of those for every configured address, so a
// match is the same pairing `ip addr` prints.
//
// Loopback is the exception: 127.0.0.1 has no entry in /proc/net/route, and the
// kernel reserves the whole 127.0.0.0/8 for the loopback device, so it resolves
// by that reservation instead of by a route.
func attributeIPv4(addr net.IP, connected []connectedRoute) (string, int, bool) {
	bestOnes := -1
	bestIface := ""
	for _, route := range connected {
		if !route.ipNet.Contains(addr) {
			continue
		}
		ones, _ := route.ipNet.Mask.Size()
		if ones > bestOnes {
			bestOnes = ones
			bestIface = route.iface
		}
	}
	if bestOnes >= 0 {
		return bestIface, bestOnes, true
	}

	if addr.IsLoopback() {
		return loopbackName, loopbackPrefix, true
	}

	return "", 0, false
}

// readProcNetRoutes reads the IPv4 routing table.
//
// Format, one route per line after a header:
//
//	Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
//	eth0  000011AC    00000000 0001 0      0   0      0000FFFF 0 0    0
//
// Destination, Gateway and Mask are 32-bit little-endian hex.
func (n *neti) readProcNetRoutes() procNetRoutes {
	f, err := n.connection.FileSystem().Open(procNetRoute)
	if err != nil {
		log.Debug().Err(err).Str("file", procNetRoute).
			Msg("os.network.interface> cannot read the IPv4 routing table")
		return procNetRoutes{gatewayFor: map[string]string{}}
	}
	defer f.Close()

	return parseProcNetRoutes(f)
}

func parseProcNetRoutes(r io.Reader) procNetRoutes {
	routes := procNetRoutes{gatewayFor: map[string]string{}}

	scanner := bufio.NewScanner(r)
	for lineNo := 0; scanner.Scan(); lineNo++ {
		if lineNo == 0 {
			continue // header
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		iface := fields[0]
		dest, destOK := hexLEToIPv4(fields[1])
		gateway, gatewayOK := hexLEToIPv4(fields[2])
		mask, maskOK := hexLEToIPv4(fields[7])
		if !destOK || !maskOK {
			continue
		}

		if gatewayOK && !gateway.Equal(net.IPv4zero) && dest.Equal(net.IPv4zero) {
			// A default route names the gateway for everything on that
			// interface. Later entries do not override an earlier one: the
			// table is ordered by metric, so the first is the one in use.
			if _, ok := routes.gatewayFor[iface]; !ok {
				routes.gatewayFor[iface] = gateway.String()
			}
			continue
		}

		// Only on-link routes attribute an address. A route via a gateway
		// describes somewhere else on the network, and a default route covers
		// every address there is, which would attribute all of them to it.
		if gatewayOK && !gateway.Equal(net.IPv4zero) {
			continue
		}
		if ones, _ := net.IPMask(mask.To4()).Size(); ones == 0 {
			continue
		}

		routes.connected = append(routes.connected, connectedRoute{
			iface: iface,
			ipNet: &net.IPNet{IP: dest.Mask(net.IPMask(mask.To4())), Mask: net.IPMask(mask.To4())},
		})
	}
	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Str("file", procNetRoute).
			Msg("os.network.interface> failed reading the IPv4 routing table")
	}

	return routes
}

// readProcNetFibTrieLocalIPv4 reads the host's own IPv4 addresses out of the
// forwarding trie.
//
// Each leaf names an address, and the lines under it describe the routes held
// for it:
//
//	|-- 172.17.0.2
//	   /32 host LOCAL
//
// A /32 LOCAL route is what the kernel installs for an address configured on an
// interface, so those leaves are the addresses. Wider LOCAL routes are not:
// loopback carries a `/8 host LOCAL` on 127.0.0.0, which is the reservation for
// the device and not an address anything is reachable at.
//
// The file prints every table, so the same address appears under Main and again
// under Local; the result is deduplicated.
func (n *neti) readProcNetFibTrieLocalIPv4() []net.IP {
	f, err := n.connection.FileSystem().Open(procNetFibTrie)
	if err != nil {
		log.Debug().Err(err).Str("file", procNetFibTrie).
			Msg("os.network.interface> cannot read the IPv4 forwarding trie")
		return nil
	}
	defer f.Close()

	return parseProcNetFibTrieLocalIPv4(f)
}

func parseProcNetFibTrieLocalIPv4(r io.Reader) []net.IP {
	var (
		addrs   []net.IP
		seen    = map[string]bool{}
		current net.IP
	)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if leaf, ok := strings.CutPrefix(line, "|-- "); ok {
			current = net.ParseIP(strings.TrimSpace(leaf))
			continue
		}

		// The alias lines belong to the leaf above them. Anything else ends
		// the leaf, so a "/32 host LOCAL" further down cannot be credited to
		// an address it does not describe.
		if !strings.HasPrefix(line, "/") {
			current = nil
			continue
		}

		if current == nil {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "/32" || fields[2] != "LOCAL" {
			continue
		}
		if key := current.String(); !seen[key] {
			seen[key] = true
			addrs = append(addrs, current)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Str("file", procNetFibTrie).
			Msg("os.network.interface> failed reading the IPv4 forwarding trie")
	}

	return addrs
}

// readProcNetIfInet6 reads the IPv6 addresses configured on each interface.
//
// Format, one address per line:
//
//	fe80000000000000003f2cfffe07b9a8 02 40 20 80 eth0
//	address (32 hex chars)           ix pl sc fl device
//
// Unlike IPv4 this names the device outright, so no route is needed to
// attribute it.
func (n *neti) readProcNetIfInet6() map[string][]IPAddress {
	f, err := n.connection.FileSystem().Open(procNetIfInet6)
	if err != nil {
		log.Debug().Err(err).Str("file", procNetIfInet6).
			Msg("os.network.interface> cannot read the IPv6 address table")
		return nil
	}
	defer f.Close()

	return parseProcNetIfInet6(f)
}

func parseProcNetIfInet6(r io.Reader) map[string][]IPAddress {
	byIface := map[string][]IPAddress{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		addr, ok := hexToIPv6Addr(fields[0])
		if !ok {
			continue
		}
		prefixLen, err := strconv.ParseInt(fields[2], 16, 32)
		if err != nil {
			log.Debug().Str("prefix", fields[2]).
				Msg("os.network.interface> skipping IPv6 address with an unreadable prefix length")
			continue
		}

		iface := fields[5]
		byIface[iface] = append(byIface[iface], NewIPv6WithPrefixLength(addr.String(), int(prefixLen)))
	}
	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Str("file", procNetIfInet6).
			Msg("os.network.interface> failed reading the IPv6 address table")
	}

	return byIface
}

// readProcNetIPv6Gateways reads the IPv6 default gateway of each interface.
//
// Format, one route per line, every address 32 hex characters:
//
//	destination plen source plen next_hop metric ref use flags device
//
// A default route is one to ::/0 through a next hop. The kernel also installs
// an unreachable ::/0 on loopback for a host with no IPv6 connectivity at all,
// and that one has no next hop, so requiring one leaves it out -- reporting it
// would give every IPv6 address a gateway of "::".
func (n *neti) readProcNetIPv6Gateways() map[string]string {
	f, err := n.connection.FileSystem().Open(procNetIPv6Route)
	if err != nil {
		log.Debug().Err(err).Str("file", procNetIPv6Route).
			Msg("os.network.interface> cannot read the IPv6 routing table")
		return nil
	}
	defer f.Close()

	return parseProcNetIPv6Gateways(f)
}

func parseProcNetIPv6Gateways(r io.Reader) map[string]string {
	gateways := map[string]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		dest, destOK := hexToIPv6Addr(fields[0])
		nextHop, nextHopOK := hexToIPv6Addr(fields[4])
		if !destOK || !nextHopOK {
			continue
		}
		if !dest.Equal(net.IPv6zero) || fields[1] != "00" {
			continue
		}
		if nextHop.Equal(net.IPv6zero) {
			continue
		}

		// The table is ordered by metric, so the first default route for an
		// interface is the one in use.
		iface := fields[9]
		if _, ok := gateways[iface]; !ok {
			gateways[iface] = nextHop.String()
		}
	}
	if err := scanner.Err(); err != nil {
		log.Debug().Err(err).Str("file", procNetIPv6Route).
			Msg("os.network.interface> failed reading the IPv6 routing table")
	}

	return gateways
}

// hexLEToIPv4 decodes the 32-bit little-endian hex procfs uses for IPv4.
func hexLEToIPv4(s string) (net.IP, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, false
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return net.IPv4(b[0], b[1], b[2], b[3]), true
}

// hexToIPv6Addr decodes the 32-character hex form procfs uses for IPv6.
func hexToIPv6Addr(s string) (net.IP, bool) {
	if len(s) != ipv6HexAddrSize {
		return nil, false
	}
	ip := make(net.IP, net.IPv6len)
	if _, err := hex.Decode(ip, []byte(s)); err != nil {
		return nil, false
	}
	return ip, true
}

// interfacesHaveNoIPs reports whether not one interface carries an address,
// which is what the sysfs detector always leaves behind and what `ip addr`
// never does -- it reports at least the loopback address on any running host.
func interfacesHaveNoIPs(interfaces []Interface) bool {
	for _, iface := range interfaces {
		if len(iface.IPAddresses) > 0 {
			return false
		}
	}
	return true
}

// interfaceNames lists the discovered interfaces, to bound what the procfs
// enrichment is allowed to report.
func interfaceNames(interfaces []Interface) []string {
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names
}
