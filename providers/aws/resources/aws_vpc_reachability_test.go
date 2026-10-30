// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
)

func TestRouteIsDefault(t *testing.T) {
	assert.True(t, routeIsDefault("0.0.0.0/0", ""))
	assert.True(t, routeIsDefault("", "::/0"))
	assert.True(t, routeIsDefault("0.0.0.0/0", "::/0"))

	// A more specific destination is not a default route on its own. Half of a
	// split default is deliberately included here: one /1 covers half the
	// address space, and it takes the pair to carry unmatched traffic, which is
	// routesReachInternet's decision rather than this one's.
	assert.False(t, routeIsDefault("10.0.0.0/16", ""))
	assert.False(t, routeIsDefault("0.0.0.0/1", ""))
	assert.False(t, routeIsDefault("128.0.0.0/1", ""))
	assert.False(t, routeIsDefault("", "2600:1f18::/56"))
	assert.False(t, routeIsDefault("", ""))
}

func TestBlockModeStopsIngress(t *testing.T) {
	assert.True(t, blockModeStopsIngress(string(ec2types.InternetGatewayBlockModeBlockBidirectional)))
	assert.True(t, blockModeStopsIngress(string(ec2types.InternetGatewayBlockModeBlockIngress)))

	assert.False(t, blockModeStopsIngress(string(ec2types.InternetGatewayBlockModeOff)))
	// A subnet the API reported no mode for is not blocking anything.
	assert.False(t, blockModeStopsIngress(""))
}

// TestInternetGatewayIdPrefix pins the distinction isPublic depends on: an
// egress-only internet gateway carries outbound IPv6 traffic only, so its ID
// must not satisfy the internet gateway prefix check.
func TestInternetGatewayIdPrefix(t *testing.T) {
	assert.True(t, hasInternetGatewayPrefix("igw-0123456789abcdef0"))
	assert.False(t, hasInternetGatewayPrefix("eigw-0123456789abcdef0"))
	assert.False(t, hasInternetGatewayPrefix("vgw-0123456789abcdef0"))
	assert.False(t, hasInternetGatewayPrefix("local"))
	assert.False(t, hasInternetGatewayPrefix(""))
}

// TestRoutesReachInternet covers the route-set decision isPublic delegates to.
// The split default (0.0.0.0/1 plus 128.0.0.0/1) covers every address between
// its two halves and carries traffic with no more specific match exactly as a
// 0.0.0.0/0 route does, so a subnet behind one is public. Only matching the
// literal default read those subnets as private.
func TestRoutesReachInternet(t *testing.T) {
	const igw = "igw-0123456789abcdef0"

	tests := []struct {
		name     string
		routes   []internetRoute
		expected bool
	}{
		{
			name:     "no routes",
			routes:   nil,
			expected: false,
		},
		{
			name:     "default route to an internet gateway",
			routes:   []internetRoute{{ipv4Cidr: "0.0.0.0/0", gatewayId: igw}},
			expected: true,
		},
		{
			name: "only local and more specific routes",
			routes: []internetRoute{
				{ipv4Cidr: "10.0.0.0/16", gatewayId: "local"},
				{ipv4Cidr: "192.168.0.0/16", gatewayId: igw},
			},
			expected: false,
		},
		{
			name: "split default to an internet gateway",
			routes: []internetRoute{
				{ipv4Cidr: "0.0.0.0/1", gatewayId: igw},
				{ipv4Cidr: "128.0.0.0/1", gatewayId: igw},
			},
			expected: true,
		},
		{
			name: "split default alongside local",
			routes: []internetRoute{
				{ipv4Cidr: "10.0.0.0/16", gatewayId: "local"},
				{ipv4Cidr: "128.0.0.0/1", gatewayId: igw},
				{ipv4Cidr: "0.0.0.0/1", gatewayId: igw},
			},
			expected: true,
		},
		{
			// One half alone leaves the other half of the address space
			// unrouted, so it does not carry unmatched traffic.
			name:     "only the lower half",
			routes:   []internetRoute{{ipv4Cidr: "0.0.0.0/1", gatewayId: igw}},
			expected: false,
		},
		{
			name:     "only the upper half",
			routes:   []internetRoute{{ipv4Cidr: "128.0.0.0/1", gatewayId: igw}},
			expected: false,
		},
		{
			// Two halves that go to different targets are not one path to the
			// internet, so they must not combine.
			name: "halves pointing at different targets",
			routes: []internetRoute{
				{ipv4Cidr: "0.0.0.0/1", gatewayId: igw},
				{ipv4Cidr: "128.0.0.0/1", gatewayId: "vgw-0123456789abcdef0"},
			},
			expected: false,
		},
		{
			// An egress-only gateway carries outbound IPv6 only, so neither a
			// default route nor a split default through one is reachable.
			name: "split default to an egress-only gateway",
			routes: []internetRoute{
				{ipv4Cidr: "0.0.0.0/1", gatewayId: "eigw-0123456789abcdef0"},
				{ipv4Cidr: "128.0.0.0/1", gatewayId: "eigw-0123456789abcdef0"},
			},
			expected: false,
		},
		{
			name: "ipv6 split default to an internet gateway",
			routes: []internetRoute{
				{ipv6Cidr: "::/1", gatewayId: igw},
				{ipv6Cidr: "8000::/1", gatewayId: igw},
			},
			expected: true,
		},
		{
			name:     "ipv6 default route to an internet gateway",
			routes:   []internetRoute{{ipv6Cidr: "::/0", gatewayId: igw}},
			expected: true,
		},
		{
			// Halves from different address families cover neither space.
			name: "one half from each address family",
			routes: []internetRoute{
				{ipv4Cidr: "0.0.0.0/1", gatewayId: igw},
				{ipv6Cidr: "8000::/1", gatewayId: igw},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, routesReachInternet(test.routes))
		})
	}
}
