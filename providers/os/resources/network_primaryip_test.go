// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

// Addresses captured from a macOS 26.6.2 host and a Debian 13 one.
func TestIsPrimaryIPCandidate(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		version uint8
		want    bool
	}{
		// Routable, and of the version asked for.
		{"global ipv4", "172.16.1.129", 4, true},
		{"private ipv4 is still routable", "10.0.2.15", 4, true},
		{"global ipv6", "2607:fb91:797d:bdcc:cf2e:18a7:75f8:33f8", 6, true},
		{"ipv6 unique local", "fd17:11c:9eaa:48a1:4d0:7daf:46e1:6276", 6, true},

		// The address this whole change is about: every IPv6 default route on
		// a Mac with a VPN client is an interface-scoped route via fe80:: on a
		// utun tunnel, and the tunnel carries nothing else.
		{"ipv6 link-local on a tunnel", "fe80::a494:2cb2:7d68:9b4a", 6, false},
		{"ipv6 link-local on a nic", "fe80::80c:4a7a:3077:d34", 6, false},
		// The same reasoning for IPv4: 169.254/16 is what a host gives itself
		// when it has no address, so it is not where the host can be reached.
		{"ipv4 link-local", "169.254.13.7", 4, false},

		// The version filter still applies.
		{"ipv6 asked for ipv4", "fd17:11c:9eaa:48a1:4d0:7daf:46e1:6276", 4, false},
		{"ipv4 asked for ipv6", "172.16.1.129", 6, false},
	}

	for _, tt := range tests {
		ip := llx.ParseIP(tt.ip)
		assert.Equal(t, tt.want, isPrimaryIPCandidate(ip, tt.version),
			"%s (%s asked as v%d)", tt.name, tt.ip, tt.version)
	}
}

// An unset address is not a candidate. primaryIPByDefaultRoute walks whatever
// the interface reports, and a resource that resolved to nothing must not
// become the primary address of the host.
func TestIsPrimaryIPCandidateUnset(t *testing.T) {
	assert.False(t, isPrimaryIPCandidate(llx.RawIP{}, 4))
	assert.False(t, isPrimaryIPCandidate(llx.RawIP{}, 6))
	assert.False(t, isPrimaryIPCandidate(llx.ParseIP("not an address"), 4))
}

// Loopback is deliberately still a candidate. A default route via lo is not a
// real configuration, so excluding it would only add a rule with nothing
// behind it -- and if a host ever does route that way, that address is the
// truth about it.
func TestIsPrimaryIPCandidateLoopback(t *testing.T) {
	assert.True(t, isPrimaryIPCandidate(llx.ParseIP("127.0.0.1"), 4))
	assert.True(t, isPrimaryIPCandidate(llx.ParseIP("::1"), 6))
}
