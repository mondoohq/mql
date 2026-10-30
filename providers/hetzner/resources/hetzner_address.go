// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"strings"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// publicAddress is the public address footprint of one project resource: the
// set of addresses a DNS record can legitimately point at to reach it.
//
// IPv6 needs two forms. Hetzner assigns a server or a primary IP a whole /64
// and the API reports that network, while a AAAA record names one address
// inside it. A load balancer reports a single address and no network. Keeping
// the network and the bare address apart is what lets one containment test
// cover the first case without loosening the second.
type publicAddress struct {
	v4    net.IP
	v6Net *net.IPNet
	v6IP  net.IP
}

// holds reports whether addr is an address this resource answers on. IPv4
// compares exactly. IPv6 is inside the assigned network when one is known, and
// otherwise compares exactly.
func (p publicAddress) holds(addr net.IP) bool {
	if len(addr) == 0 {
		return false
	}
	if addr.To4() != nil {
		return p.v4 != nil && p.v4.Equal(addr)
	}
	if p.v6Net != nil && p.v6Net.Contains(addr) {
		return true
	}
	return p.v6IP != nil && p.v6IP.Equal(addr)
}

// empty reports whether the resource publishes no public address at all, which
// is the case for a server created without public networking.
func (p publicAddress) empty() bool {
	return p.v4 == nil && p.v6Net == nil && p.v6IP == nil
}

// normalizeIP collapses the zero-length net.IP the SDK uses for an absent
// address to nil, so a missing address never compares equal to anything.
func normalizeIP(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	return ip
}

func serverPublicAddress(n hcloud.ServerPublicNet) publicAddress {
	return publicAddress{
		v4:    normalizeIP(n.IPv4.IP),
		v6Net: n.IPv6.Network,
		v6IP:  normalizeIP(n.IPv6.IP),
	}
}

// loadBalancerPublicAddress reads the two single addresses a load balancer
// answers on. The API reports no network for either family, so both compare
// exactly.
func loadBalancerPublicAddress(n hcloud.LoadBalancerPublicNet) publicAddress {
	return publicAddress{
		v4:   normalizeIP(n.IPv4.IP),
		v6IP: normalizeIP(n.IPv6.IP),
	}
}

// singleAddress builds the footprint of a primary or floating IP. Each carries
// one address, in one family, plus the assigned network for IPv6.
func singleAddress(ip net.IP, network *net.IPNet) publicAddress {
	ip = normalizeIP(ip)
	if ip != nil && ip.To4() != nil {
		return publicAddress{v4: ip}
	}
	return publicAddress{v6Net: network, v6IP: ip}
}

// addressRecordTypes are the record types whose value is an IP address.
var addressRecordTypes = map[string]bool{"A": true, "AAAA": true}

// recordAddress parses the address a DNS record publishes.
//
// The second return reports whether the record type carries an address at all.
// That separates "this name points at nothing the project holds" from "the
// question does not apply", which is why a TXT or CNAME record reports null
// rather than false: a false would make every one of them look dangling to a
// sweep looking for records that resolve outside the project.
//
// A value that does not parse yields a nil address with true, because a
// malformed A record genuinely resolves to nothing the project holds.
func recordAddress(recordType, value string) (net.IP, bool) {
	if !addressRecordTypes[strings.ToUpper(strings.TrimSpace(recordType))] {
		return nil, false
	}
	return net.ParseIP(strings.TrimSpace(value)), true
}
