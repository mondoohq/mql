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

func privateNetServer(id, networkID int64, ip string, aliases ...string) *hcloud.Server {
	alias := make([]net.IP, 0, len(aliases))
	for _, a := range aliases {
		alias = append(alias, net.ParseIP(a))
	}
	return &hcloud.Server{
		ID: id,
		PrivateNet: []hcloud.ServerPrivateNet{{
			Network: &hcloud.Network{ID: networkID},
			IP:      net.ParseIP(ip),
			Aliases: alias,
		}},
	}
}

func TestServerHoldingPrivateIP(t *testing.T) {
	gateway := net.ParseIP("10.0.0.2")

	t.Run("no servers", func(t *testing.T) {
		assert.Nil(t, serverHoldingPrivateIP(nil, 1, gateway))
	})

	t.Run("nil gateway", func(t *testing.T) {
		servers := []*hcloud.Server{privateNetServer(10, 1, "10.0.0.2")}
		assert.Nil(t, serverHoldingPrivateIP(servers, 1, nil))
	})

	t.Run("matches the interface address", func(t *testing.T) {
		servers := []*hcloud.Server{
			privateNetServer(10, 1, "10.0.0.3"),
			privateNetServer(20, 1, "10.0.0.2"),
		}
		got := serverHoldingPrivateIP(servers, 1, gateway)
		require.NotNil(t, got)
		assert.Equal(t, int64(20), got.ID)
	})

	// A NAT gateway commonly carries the routed address as an alias rather
	// than as its interface address, so an alias-only match must still name
	// the host. Missing it would report the egress path as unowned.
	t.Run("matches an alias address", func(t *testing.T) {
		servers := []*hcloud.Server{privateNetServer(30, 1, "10.0.0.9", "10.0.0.2")}
		got := serverHoldingPrivateIP(servers, 1, gateway)
		require.NotNil(t, got)
		assert.Equal(t, int64(30), got.ID)
	})

	// Two networks in one project can carry overlapping ranges, so an address
	// alone does not identify a server. Matching across networks would name
	// the wrong host as the gateway.
	t.Run("does not match across networks", func(t *testing.T) {
		servers := []*hcloud.Server{privateNetServer(40, 2, "10.0.0.2")}
		assert.Nil(t, serverHoldingPrivateIP(servers, 1, gateway))
	})

	t.Run("no server holds the address", func(t *testing.T) {
		servers := []*hcloud.Server{privateNetServer(50, 1, "10.0.0.7")}
		assert.Nil(t, serverHoldingPrivateIP(servers, 1, gateway))
	})

	t.Run("skips nil servers and unattached entries", func(t *testing.T) {
		servers := []*hcloud.Server{
			nil,
			{ID: 60, PrivateNet: []hcloud.ServerPrivateNet{{Network: nil, IP: gateway}}},
			privateNetServer(70, 1, "10.0.0.2"),
		}
		got := serverHoldingPrivateIP(servers, 1, gateway)
		require.NotNil(t, got)
		assert.Equal(t, int64(70), got.ID)
	})

	// IPv4 addresses reach Go as either a 4-byte or a 16-byte slice depending
	// on how they were parsed. A bytes comparison would miss the pair; IP.Equal
	// is what makes the two forms compare equal.
	t.Run("matches across 4-byte and 16-byte forms", func(t *testing.T) {
		four := net.IPv4(10, 0, 0, 2).To4()
		servers := []*hcloud.Server{{
			ID:         80,
			PrivateNet: []hcloud.ServerPrivateNet{{Network: &hcloud.Network{ID: 1}, IP: four}},
		}}
		got := serverHoldingPrivateIP(servers, 1, gateway)
		require.NotNil(t, got)
		assert.Equal(t, int64(80), got.ID)
	})
}

func TestNetworkRouteID(t *testing.T) {
	assert.Equal(t, "hetzner.network.route/7/0.0.0.0/0", networkRouteID(7, "0.0.0.0/0"))

	// Two routes on one network always differ by destination, so the key
	// separates them. Colliding keys would collapse them into one resource.
	assert.NotEqual(t,
		networkRouteID(7, "0.0.0.0/0"),
		networkRouteID(7, "10.1.0.0/16"),
	)
	assert.NotEqual(t,
		networkRouteID(7, "0.0.0.0/0"),
		networkRouteID(8, "0.0.0.0/0"),
	)
}
