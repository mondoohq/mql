// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
)

// privateOrReservedCIDRs are address ranges that are not routable from the
// public internet. A security-group rule whose source is wholly inside one of
// these does not constitute internet exposure.
var privateOrReservedCIDRs = mustParseCIDRs(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local
	"100.64.0.0/10",  // carrier-grade NAT
	"0.0.0.0/8",      // "this host on this network" (RFC1122)
	"240.0.0.0/4",    // reserved for future use
	"2001:db8::/32",  // IPv6 documentation (RFC3849)
	"::1/128",        // IPv6 loopback
	"fc00::/7",       // IPv6 unique local
	"fe80::/10",      // IPv6 link-local
)

// broadPublicPrefix* is the largest prefix length still treated as "broad"
// internet exposure rather than a specific allow-listed host or network: a /8
// IPv4 block (16M+ addresses) or a /32 IPv6 block. The threshold is deliberately
// conservative — narrower public ranges (a single /32 host, a corporate /24) are
// treated as scoped to avoid false positives on legitimate large allow-lists.
const (
	broadPublicPrefixV4 = 8
	broadPublicPrefixV6 = 32
)

// mustParseCIDRs parses a fixed set of CIDR literals at init time, panicking on
// a malformed entry so a typo in the private/reserved list fails loudly rather
// than silently shrinking the set.
func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("mustParseCIDRs: %s: %v", c, err))
		}
		nets = append(nets, n)
	}
	return nets
}

// cidrIsPublic reports whether a CIDR exposes a broad slice of the public
// internet — the all-addresses 0.0.0.0/0 or ::/0, or any wide block (prefix
// length at or below the broad-public threshold) that is not contained within a
// private or reserved range. A specific public host or a narrow allow-listed
// range is not considered public.
func cidrIsPublic(cidr string) bool {
	if cidr == "" {
		return false
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	threshold := broadPublicPrefixV4
	if bits > 32 {
		threshold = broadPublicPrefixV6
	}
	if ones > threshold {
		return false
	}
	for _, pr := range privateOrReservedCIDRs {
		if cidrWithin(ipnet, pr) {
			return false
		}
	}
	return true
}

// cidrWithin reports whether inner is entirely contained within outer.
func cidrWithin(inner, outer *net.IPNet) bool {
	innerOnes, innerBits := inner.Mask.Size()
	outerOnes, outerBits := outer.Mask.Size()
	if innerBits != outerBits || outerOnes > innerOnes {
		return false
	}
	return outer.Contains(inner.IP)
}

// addressIsPublic reports whether an address-group member exposes a broad slice
// of the public internet. Members come in three shapes: a CIDR, an inclusive
// range written "start-end", or a bare address. A bare address is a single host
// and so is never broad.
func addressIsPublic(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	// Splitting on "-" is unambiguous: neither CIDRs nor IPv6 literals use it.
	if start, end, isRange := strings.Cut(addr, "-"); isRange {
		return ipRangeIsPublic(start, end)
	}
	if strings.Contains(addr, "/") {
		return cidrIsPublic(addr)
	}
	return false
}

// ipRangeIsPublic applies the same test as cidrIsPublic to an inclusive IP
// range: the range must span at least as many addresses as a block at the
// broad-public prefix length, and must not lie wholly inside a private or
// reserved range.
func ipRangeIsPublic(startStr, endStr string) bool {
	start, err := netip.ParseAddr(strings.TrimSpace(startStr))
	if err != nil {
		return false
	}
	end, err := netip.ParseAddr(strings.TrimSpace(endStr))
	if err != nil {
		return false
	}
	start, end = start.Unmap(), end.Unmap()
	if start.Is4() != end.Is4() || end.Less(start) {
		return false
	}

	if rangeSize(start, end).Cmp(broadRangeSize(start.Is4())) < 0 {
		return false
	}

	// A range is contiguous and so is a CIDR, so both endpoints falling inside
	// one private or reserved block puts the whole range inside it.
	startIP, endIP := net.IP(start.AsSlice()), net.IP(end.AsSlice())
	for _, pr := range privateOrReservedCIDRs {
		if pr.Contains(startIP) && pr.Contains(endIP) {
			return false
		}
	}
	return true
}

// rangeSize returns the inclusive count of addresses from start to end.
func rangeSize(start, end netip.Addr) *big.Int {
	s := new(big.Int).SetBytes(start.AsSlice())
	e := new(big.Int).SetBytes(end.AsSlice())
	return e.Sub(e, s).Add(e, big.NewInt(1))
}

// broadRangeSize returns the number of addresses in a block at the broad-public
// prefix length, the span at which a range counts as internet exposure.
func broadRangeSize(is4 bool) *big.Int {
	if is4 {
		return new(big.Int).Lsh(big.NewInt(1), 32-broadPublicPrefixV4)
	}
	return new(big.Int).Lsh(big.NewInt(1), 128-broadPublicPrefixV6)
}

// anyCidrPublic reports whether any CIDR string in the list exposes the public
// internet.
func anyCidrPublic(cidrs []any) bool {
	for _, c := range cidrs {
		if s, ok := c.(string); ok && cidrIsPublic(s) {
			return true
		}
	}
	return false
}
