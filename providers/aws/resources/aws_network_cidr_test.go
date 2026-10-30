// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeProtocol(t *testing.T) {
	assert.Equal(t, protocolTcp, normalizeProtocol("tcp"))
	assert.Equal(t, protocolTcp, normalizeProtocol("TCP"))
	assert.Equal(t, protocolTcp, normalizeProtocol("6"))
	assert.Equal(t, protocolUdp, normalizeProtocol("udp"))
	assert.Equal(t, protocolIcmp, normalizeProtocol("icmp"))
	assert.Equal(t, protocolIcmpv6, normalizeProtocol("icmpv6"))
	assert.Equal(t, protocolIcmpv6, normalizeProtocol("58"))

	// All the ways "every protocol" is spelled.
	assert.Equal(t, protocolAll, normalizeProtocol("-1"))
	assert.Equal(t, protocolAll, normalizeProtocol("all"))
	assert.Equal(t, protocolAll, normalizeProtocol(""))

	// An unrecognized protocol is preserved so two of the same still match.
	assert.Equal(t, "132", normalizeProtocol("132"))
}

func TestProtocolCovers(t *testing.T) {
	assert.True(t, protocolCovers("-1", "tcp"))
	assert.True(t, protocolCovers("tcp", "tcp"))
	assert.True(t, protocolCovers("tcp", "6"), "name and number are the same protocol")
	assert.True(t, protocolCovers("6", "tcp"))

	assert.False(t, protocolCovers("tcp", "udp"))
	assert.False(t, protocolCovers("tcp", "-1"), "a single protocol cannot cover all protocols")
	assert.False(t, protocolCovers("icmp", "icmpv6"))
}

func TestCidrCovers(t *testing.T) {
	assert.True(t, cidrCovers("0.0.0.0/0", "10.0.0.0/8"))
	assert.True(t, cidrCovers("10.0.0.0/8", "10.1.0.0/16"))
	assert.True(t, cidrCovers("10.0.0.0/8", "10.0.0.0/8"), "a range covers itself")
	assert.True(t, cidrCovers("::/0", "2600:1f18::/56"))

	assert.False(t, cidrCovers("10.0.0.0/8", "0.0.0.0/0"), "a smaller range cannot cover a larger one")
	assert.False(t, cidrCovers("10.1.0.0/16", "10.2.0.0/16"), "sibling ranges do not cover each other")
	assert.False(t, cidrCovers("192.168.0.0/16", "10.0.0.0/8"))

	// Address families never overlap. This is the case that made an IPv4
	// deny-all appear to shadow an IPv6 allow-all.
	assert.False(t, cidrCovers("0.0.0.0/0", "::/0"))
	assert.False(t, cidrCovers("::/0", "0.0.0.0/0"))

	// An unrecorded outer source covers anything; an unrecorded inner source
	// cannot be placed inside a specific range.
	assert.True(t, cidrCovers("", "10.0.0.0/8"))
	assert.True(t, cidrCovers("", ""))
	assert.False(t, cidrCovers("10.0.0.0/8", ""))

	// Unparseable input never matches.
	assert.False(t, cidrCovers("not-a-cidr", "10.0.0.0/8"))
	assert.False(t, cidrCovers("10.0.0.0/8", "not-a-cidr"))
	assert.False(t, cidrCovers("10.0.0.0/33", "10.0.0.0/8"))
}

func TestCidrsOverlap(t *testing.T) {
	assert.True(t, cidrsOverlap("0.0.0.0/0", "10.0.0.0/8"))
	assert.True(t, cidrsOverlap("10.0.0.0/8", "0.0.0.0/0"), "overlap is symmetric")
	assert.True(t, cidrsOverlap("10.0.0.0/8", "10.1.0.0/16"))
	assert.True(t, cidrsOverlap("10.0.0.0/8", "10.0.0.0/8"))

	assert.False(t, cidrsOverlap("10.1.0.0/16", "10.2.0.0/16"))
	assert.False(t, cidrsOverlap("0.0.0.0/0", "::/0"), "different families never overlap")
	assert.False(t, cidrsOverlap("", "10.0.0.0/8"))
	assert.False(t, cidrsOverlap("bad", "10.0.0.0/8"))
}

func TestNewPortRange(t *testing.T) {
	r := newPortRange(80, 443)
	assert.Equal(t, int64(80), r.from)
	assert.Equal(t, int64(443), r.to)
	assert.False(t, r.all)

	// -1 is how both security groups and network ACLs spell "unset", which for
	// a protocol with no ports means every port.
	assert.True(t, newPortRange(-1, -1).all)
	assert.True(t, newPortRange(-1, 443).all)

	// A reversed range is normalized rather than treated as empty.
	reversed := newPortRange(443, 80)
	assert.Equal(t, int64(80), reversed.from)
	assert.Equal(t, int64(443), reversed.to)
}

func TestSecurityGroupRulePorts(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		from, to int64
		wantOk   bool
		want     portRange
	}{
		{"all traffic", "-1", -1, -1, true, portRange{from: 0, to: maxPort}},
		{"tcp single port", "tcp", 22, 22, true, portRange{from: 22, to: 22}},
		{"tcp range", "tcp", 20, 25, true, portRange{from: 20, to: 25}},
		{"tcp by number", "6", 3389, 3389, true, portRange{from: 3389, to: 3389}},
		{"udp full range", "udp", 0, 65535, true, portRange{from: 0, to: maxPort}},
		{"udp by number", "17", 53, 53, true, portRange{from: 53, to: 53}},
		{"tcp unset range", "tcp", -1, -1, true, portRange{from: 0, to: maxPort}},
		// ICMP reuses fromPort and toPort for type and code: type 8 code 0 is
		// echo request, not a port range 0 to 8.
		{"icmp echo", "icmp", 8, 0, false, portRange{}},
		{"icmp all types", "icmp", -1, -1, false, portRange{}},
		{"icmpv6", "icmpv6", -1, -1, false, portRange{}},
		{"icmp by number", "1", 3, 4, false, portRange{}},
		{"esp", "50", -1, -1, false, portRange{}},
		{"unset protocol", "", -1, -1, false, portRange{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := securityGroupRulePorts(tt.protocol, tt.from, tt.to)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPortRangeCovers(t *testing.T) {
	all := portRange{all: true}
	assert.True(t, all.covers(newPortRange(443, 443)))
	assert.True(t, all.covers(all))

	assert.True(t, newPortRange(0, 65535).covers(newPortRange(443, 443)))
	assert.True(t, newPortRange(443, 443).covers(newPortRange(443, 443)))
	assert.True(t, newPortRange(80, 8443).covers(newPortRange(443, 443)))

	assert.False(t, newPortRange(443, 443).covers(newPortRange(80, 443)))
	assert.False(t, newPortRange(400, 500).covers(newPortRange(443, 8443)))
	assert.False(t, newPortRange(0, 65535).covers(all), "a bounded range cannot cover all ports")
}

func TestPortRangeOverlaps(t *testing.T) {
	all := portRange{all: true}
	assert.True(t, all.overlaps(newPortRange(443, 443)))
	assert.True(t, newPortRange(443, 443).overlaps(all))

	assert.True(t, newPortRange(80, 500).overlaps(newPortRange(443, 8443)))
	assert.True(t, newPortRange(443, 443).overlaps(newPortRange(443, 443)))
	// Touching at a single port still overlaps.
	assert.True(t, newPortRange(80, 443).overlaps(newPortRange(443, 8443)))

	assert.False(t, newPortRange(80, 442).overlaps(newPortRange(443, 8443)))
	assert.False(t, newPortRange(8443, 8443).overlaps(newPortRange(80, 443)))
}
