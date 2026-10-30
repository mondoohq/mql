// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"strings"
)

// Protocol numbers as they appear in a network ACL entry. Security group rules
// name the protocol instead ("tcp"), so the two have to be compared on a common
// form before a rule can be matched against an ACL entry.
const (
	protocolAll    = "-1"
	protocolIcmp   = "1"
	protocolTcp    = "6"
	protocolUdp    = "17"
	protocolIcmpv6 = "58"
)

// normalizeProtocol converts a protocol as written in either a security group
// rule or a network ACL entry into its protocol number. Security groups use
// names ("tcp", "udp", "icmp", "icmpv6") and the wildcard "-1"; network ACLs use
// the number directly. An unrecognized value is returned unchanged so two
// entries carrying the same unusual protocol still compare equal.
func normalizeProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "-1", "all":
		return protocolAll
	case "tcp":
		return protocolTcp
	case "udp":
		return protocolUdp
	case "icmp":
		return protocolIcmp
	case "icmpv6", "58":
		return protocolIcmpv6
	default:
		return protocol
	}
}

// protocolCovers reports whether a rule for protocol outer applies to every
// packet a rule for protocol inner applies to. The all-protocols wildcard covers
// everything; otherwise the protocols must be the same.
func protocolCovers(outer, inner string) bool {
	o, i := normalizeProtocol(outer), normalizeProtocol(inner)
	return o == protocolAll || o == i
}

// parseCidr parses an IPv4 or IPv6 CIDR block, returning false for anything
// unparseable rather than an error: rule evaluation treats a CIDR it cannot read
// as non-matching, and a malformed value from the API should not fail a query.
func parseCidr(cidr string) (*net.IPNet, bool) {
	if cidr == "" {
		return nil, false
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, false
	}
	return network, true
}

// isIPv4Network reports which address family a parsed CIDR belongs to. An IPv4
// and an IPv6 range never overlap, so the family gates every comparison below.
func isIPv4Network(network *net.IPNet) bool {
	return network.IP.To4() != nil
}

// cidrCovers reports whether outer contains every address in inner.
//
// An empty outer means "no source restriction recorded" and covers anything,
// which keeps callers that do not track a CIDR working unchanged. An empty inner
// is only covered by an equally unrestricted outer, since an unknown source
// cannot be shown to fall inside a specific range.
func cidrCovers(outer, inner string) bool {
	if outer == "" {
		return true
	}
	if inner == "" {
		return false
	}

	outerNet, ok := parseCidr(outer)
	if !ok {
		return false
	}
	innerNet, ok := parseCidr(inner)
	if !ok {
		return false
	}
	if isIPv4Network(outerNet) != isIPv4Network(innerNet) {
		return false
	}

	outerOnes, _ := outerNet.Mask.Size()
	innerOnes, _ := innerNet.Mask.Size()
	if outerOnes > innerOnes {
		// A longer prefix is a smaller range and cannot contain a shorter one.
		return false
	}
	return outerNet.Contains(innerNet.IP)
}

// cidrsOverlap reports whether two CIDR blocks share at least one address.
// Overlap without containment is what makes a network ACL verdict partial: some
// of the traffic a rule permits is decided by the entry and some falls through
// to later entries.
func cidrsOverlap(a, b string) bool {
	aNet, ok := parseCidr(a)
	if !ok {
		return false
	}
	bNet, ok := parseCidr(b)
	if !ok {
		return false
	}
	if isIPv4Network(aNet) != isIPv4Network(bNet) {
		return false
	}
	return aNet.Contains(bNet.IP) || bNet.Contains(aNet.IP)
}

// portRange is an inclusive TCP/UDP port span. all is true when the rule carries
// no explicit range, which means every port for the protocol.
type portRange struct {
	from int64
	to   int64
	all  bool
}

// newPortRange builds a port range from the from/to pair a security group rule
// or network ACL entry carries. Both resources use -1 to mean "unset", and a
// protocol with no port concept (ICMP, or the all-protocols wildcard) spans
// every port.
func newPortRange(from, to int64) portRange {
	if from < 0 || to < 0 {
		return portRange{all: true}
	}
	if from > to {
		from, to = to, from
	}
	return portRange{from: from, to: to}
}

// maxPort is the highest TCP or UDP port number.
const maxPort = 65535

// securityGroupRulePorts returns the TCP and UDP ports a security group rule
// admits. ok is false for a rule whose protocol carries no ports: ICMP, where
// fromPort and toPort hold the ICMP type and code, and any other IP protocol
// such as ESP. An all-traffic rule admits every port, and so does a TCP or UDP
// rule whose range is unset.
func securityGroupRulePorts(protocol string, from, to int64) (portRange, bool) {
	if strings.TrimSpace(protocol) == "" {
		return portRange{}, false
	}
	switch normalizeProtocol(protocol) {
	case protocolAll:
		return portRange{from: 0, to: maxPort}, true
	case protocolTcp, protocolUdp:
		r := newPortRange(from, to)
		if r.all {
			return portRange{from: 0, to: maxPort}, true
		}
		return r, true
	default:
		return portRange{}, false
	}
}

// covers reports whether every port in other falls inside r.
func (r portRange) covers(other portRange) bool {
	if r.all {
		return true
	}
	if other.all {
		// other spans every port; a bounded range cannot contain it.
		return false
	}
	return r.from <= other.from && r.to >= other.to
}

// overlaps reports whether r and other share at least one port.
func (r portRange) overlaps(other portRange) bool {
	if r.all || other.all {
		return true
	}
	return r.from <= other.to && other.from <= r.to
}
