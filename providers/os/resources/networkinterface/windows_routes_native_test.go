// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package networkinterface

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

func TestFormatDestination(t *testing.T) {
	w := &windowsRouteDetector{}

	tests := []struct {
		name      string
		ip        net.IP
		prefixLen int
		want      string
	}{
		{
			name:      "nil IP returns empty",
			ip:        nil,
			prefixLen: 0,
			want:      "",
		},
		{
			name:      "IPv4 zero address",
			ip:        net.IPv4zero,
			prefixLen: 0,
			want:      "0.0.0.0/0",
		},
		{
			name:      "IPv6 unspecified",
			ip:        net.IPv6unspecified,
			prefixLen: 0,
			want:      "::/0",
		},
		{
			name:      "regular IPv4 with prefix",
			ip:        net.ParseIP("192.168.1.0"),
			prefixLen: 24,
			want:      "192.168.1.0/24",
		},
		{
			name:      "regular IPv6 with prefix",
			ip:        net.ParseIP("fe80::1"),
			prefixLen: 64,
			want:      "fe80::1/64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := w.formatDestination(tt.ip, tt.prefixLen)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatGateway(t *testing.T) {
	w := &windowsRouteDetector{}

	tests := []struct {
		name   string
		ip     net.IP
		family uint16
		want   string
	}{
		{
			name:   "nil gateway IPv4",
			ip:     nil,
			family: AF_INET,
			want:   "0.0.0.0",
		},
		{
			name:   "nil gateway IPv6",
			ip:     nil,
			family: AF_INET6,
			want:   "::",
		},
		{
			name:   "IPv4 unspecified",
			ip:     net.IPv4zero,
			family: AF_INET,
			want:   "0.0.0.0",
		},
		{
			name:   "IPv6 unspecified",
			ip:     net.IPv6unspecified,
			family: AF_INET6,
			want:   "::",
		},
		{
			name:   "regular IPv4 gateway",
			ip:     net.ParseIP("192.168.1.1"),
			family: AF_INET,
			want:   "192.168.1.1",
		},
		{
			name:   "regular IPv6 gateway",
			ip:     net.ParseIP("fe80::1"),
			family: AF_INET6,
			want:   "fe80::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := w.formatGateway(tt.ip, tt.family)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetInterfaceName(t *testing.T) {
	w := &windowsRouteDetector{}

	interfaceMap := map[uint32]string{
		1:  "Loopback Pseudo-Interface 1",
		13: "Ethernet",
	}

	t.Run("found in map", func(t *testing.T) {
		assert.Equal(t, "Ethernet", w.getInterfaceName(13, interfaceMap))
	})

	t.Run("not found falls back to index string", func(t *testing.T) {
		assert.Equal(t, "99", w.getInterfaceName(99, interfaceMap))
	})
}

func TestParseSockaddrInet(t *testing.T) {
	w := &windowsRouteDetector{}

	t.Run("IPv4 address", func(t *testing.T) {
		var addr socketInetAddress
		// Set family to AF_INET
		addr.Data[0] = byte(AF_INET)
		addr.Data[1] = byte(AF_INET >> 8)
		// Set IP address bytes at offset 4 (SinAddr in ipv4Address)
		addr.Data[4] = 192
		addr.Data[5] = 168
		addr.Data[6] = 1
		addr.Data[7] = 1

		ip, _, err := w.parseSockaddrInet(addr, AF_INET)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", ip.To4().String())
	})

	t.Run("IPv6 address", func(t *testing.T) {
		var addr socketInetAddress
		// Set family to AF_INET6
		addr.Data[0] = byte(AF_INET6)
		addr.Data[1] = byte(AF_INET6 >> 8)
		// Set IPv6 loopback at offset 8 (Sin6Addr in ipv6Address)
		addr.Data[8+15] = 1 // ::1

		ip, _, err := w.parseSockaddrInet(addr, AF_INET6)
		require.NoError(t, err)
		assert.Equal(t, "::1", ip.String())
	})

	t.Run("unsupported family", func(t *testing.T) {
		var addr socketInetAddress
		_, _, err := w.parseSockaddrInet(addr, 99)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported address family")
	})
}

func TestList_Integration(t *testing.T) {
	// List reads the routing table natively only for a local connection.
	w := &windowsRouteDetector{
		conn:     local.NewConnection(0, &inventory.Config{}, &inventory.Asset{}),
		platform: windowsPlatform,
	}
	routes, err := w.List()
	require.NoError(t, err)
	require.NotEmpty(t, routes, "expected at least one route on a Windows machine")

	// Every Windows machine should have at least one route with a non-empty destination
	foundNonEmpty := false
	for _, r := range routes {
		if r.Destination != "" {
			foundNonEmpty = true
			break
		}
	}
	assert.True(t, foundNonEmpty, "expected at least one route with a non-empty destination")
}
