// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return n
}

// A server publishes a single IPv4 address and an entire IPv6 network, so the
// two families need different comparisons. Testing them together on one
// footprint is what catches a v6 test accidentally written as equality.
func TestServerPublicAddressHolds(t *testing.T) {
	addr := serverPublicAddress(hcloud.ServerPublicNet{
		IPv4: hcloud.ServerPublicNetIPv4{IP: net.ParseIP("203.0.113.10")},
		IPv6: hcloud.ServerPublicNetIPv6{
			IP:      net.ParseIP("2001:db8:1234:5678::1"),
			Network: mustCIDR(t, "2001:db8:1234:5678::/64"),
		},
	})

	t.Run("ipv4 matches exactly", func(t *testing.T) {
		assert.True(t, addr.holds(net.ParseIP("203.0.113.10")))
	})

	t.Run("different ipv4 does not match", func(t *testing.T) {
		assert.False(t, addr.holds(net.ParseIP("203.0.113.11")))
	})

	// The whole point of the containment test: Hetzner reports the /64 while a
	// AAAA record names one address inside it. Equality would report every
	// such record as pointing outside the project.
	t.Run("ipv6 inside the assigned network matches", func(t *testing.T) {
		assert.True(t, addr.holds(net.ParseIP("2001:db8:1234:5678::dead:beef")))
	})

	t.Run("ipv6 base address matches", func(t *testing.T) {
		assert.True(t, addr.holds(net.ParseIP("2001:db8:1234:5678::1")))
	})

	t.Run("ipv6 outside the assigned network does not match", func(t *testing.T) {
		assert.False(t, addr.holds(net.ParseIP("2001:db8:1234:9999::1")))
	})

	t.Run("nil address does not match", func(t *testing.T) {
		assert.False(t, addr.holds(nil))
	})
}

// A server created without public networking must match nothing. The SDK
// reports absent addresses as a zero-length net.IP rather than nil, which is
// the case normalizeIP exists to collapse.
func TestServerPublicAddressWithoutPublicNet(t *testing.T) {
	addr := serverPublicAddress(hcloud.ServerPublicNet{})

	assert.True(t, addr.empty())
	assert.False(t, addr.holds(net.ParseIP("203.0.113.10")))
	assert.False(t, addr.holds(net.ParseIP("2001:db8::1")))
}

func TestServerPublicAddressIPv4Only(t *testing.T) {
	addr := serverPublicAddress(hcloud.ServerPublicNet{
		IPv4: hcloud.ServerPublicNetIPv4{IP: net.ParseIP("203.0.113.10")},
	})

	assert.False(t, addr.empty())
	assert.True(t, addr.holds(net.ParseIP("203.0.113.10")))
	assert.False(t, addr.holds(net.ParseIP("2001:db8::1")))
}

// A load balancer reports single addresses and no network for either family,
// so its IPv6 must compare exactly. Treating it like a server would match a
// whole /64 the balancer does not own.
func TestLoadBalancerPublicAddressHolds(t *testing.T) {
	addr := loadBalancerPublicAddress(hcloud.LoadBalancerPublicNet{
		IPv4: hcloud.LoadBalancerPublicNetIPv4{IP: net.ParseIP("203.0.113.50")},
		IPv6: hcloud.LoadBalancerPublicNetIPv6{IP: net.ParseIP("2001:db8:abcd::1")},
	})

	assert.True(t, addr.holds(net.ParseIP("203.0.113.50")))
	assert.True(t, addr.holds(net.ParseIP("2001:db8:abcd::1")))
	assert.False(t, addr.holds(net.ParseIP("2001:db8:abcd::2")))
	assert.False(t, addr.holds(net.ParseIP("203.0.113.51")))
}

func TestSingleAddress(t *testing.T) {
	t.Run("ipv4 primary ip", func(t *testing.T) {
		addr := singleAddress(net.ParseIP("203.0.113.20"), nil)
		assert.True(t, addr.holds(net.ParseIP("203.0.113.20")))
		assert.False(t, addr.holds(net.ParseIP("203.0.113.21")))
	})

	t.Run("ipv6 primary ip matches inside its network", func(t *testing.T) {
		addr := singleAddress(net.ParseIP("2001:db8:5::"), mustCIDR(t, "2001:db8:5::/64"))
		assert.True(t, addr.holds(net.ParseIP("2001:db8:5::abcd")))
		assert.False(t, addr.holds(net.ParseIP("2001:db8:6::abcd")))
	})

	// Falls back to comparing the bare address when the API reports no
	// network, so a record still resolves rather than silently missing.
	t.Run("ipv6 without a network compares exactly", func(t *testing.T) {
		addr := singleAddress(net.ParseIP("2001:db8:7::9"), nil)
		assert.True(t, addr.holds(net.ParseIP("2001:db8:7::9")))
		assert.False(t, addr.holds(net.ParseIP("2001:db8:7::a")))
	})

	t.Run("absent address matches nothing", func(t *testing.T) {
		addr := singleAddress(nil, nil)
		assert.True(t, addr.empty())
		assert.False(t, addr.holds(net.ParseIP("203.0.113.20")))
	})
}

// The bool separating "carries an address" from "does not" is what keeps a
// TXT or CNAME record out of a sweep for records pointing outside the project.
// Reporting false for them would make every one of them look dangling.
func TestRecordAddress(t *testing.T) {
	t.Run("A record carries an address", func(t *testing.T) {
		ip, carries := recordAddress("A", "203.0.113.10")
		assert.True(t, carries)
		assert.Equal(t, net.ParseIP("203.0.113.10"), ip)
	})

	t.Run("AAAA record carries an address", func(t *testing.T) {
		ip, carries := recordAddress("AAAA", "2001:db8::1")
		assert.True(t, carries)
		assert.Equal(t, net.ParseIP("2001:db8::1"), ip)
	})

	for _, recordType := range []string{"CNAME", "TXT", "MX", "NS", "CAA", "DS", "SRV", "PTR"} {
		t.Run(recordType+" carries no address", func(t *testing.T) {
			ip, carries := recordAddress(recordType, "example.com.")
			assert.False(t, carries)
			assert.Nil(t, ip)
		})
	}

	t.Run("type comparison ignores case and padding", func(t *testing.T) {
		ip, carries := recordAddress(" aaaa ", "2001:db8::1")
		assert.True(t, carries)
		assert.Equal(t, net.ParseIP("2001:db8::1"), ip)
	})

	t.Run("value padding is trimmed", func(t *testing.T) {
		ip, carries := recordAddress("A", " 203.0.113.10 ")
		assert.True(t, carries)
		assert.Equal(t, net.ParseIP("203.0.113.10"), ip)
	})

	// A malformed address record still carries an address, it just resolves to
	// nothing. Reporting it as "carries none" would hide it from the sweep.
	t.Run("malformed value carries an address that parses to nothing", func(t *testing.T) {
		ip, carries := recordAddress("A", "not-an-ip")
		assert.True(t, carries)
		assert.Nil(t, ip)
	})

	t.Run("empty value carries an address that parses to nothing", func(t *testing.T) {
		ip, carries := recordAddress("A", "")
		assert.True(t, carries)
		assert.Nil(t, ip)
	})
}

// A record that parses to nothing must not match a resource whose own address
// is absent, which is what a naive nil-equals-nil comparison would do.
func TestUnparseableRecordMatchesNothing(t *testing.T) {
	ip, carries := recordAddress("A", "not-an-ip")
	require.True(t, carries)

	server := serverPublicAddress(hcloud.ServerPublicNet{})
	assert.False(t, server.holds(ip))

	withAddress := serverPublicAddress(hcloud.ServerPublicNet{
		IPv4: hcloud.ServerPublicNetIPv4{IP: net.ParseIP("203.0.113.10")},
	})
	assert.False(t, withAddress.holds(ip))
}
