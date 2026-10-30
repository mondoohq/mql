// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package networkinterface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"golang.org/x/net/route"
)

func Test_parseRouteMessage(t *testing.T) {
	pf := &inventory.Platform{
		Family: []string{"darwin"},
	}
	d := &darwinRouteDetector{conn: nil, platform: pf}

	// Create interface map for testing
	interfaceMap := map[int]string{
		1:  "lo0",
		11: "en0",
		29: "bridge100",
	}

	tests := []struct {
		name              string
		routeMsg          *route.RouteMessage
		expectedDest      string
		expectedGateway   string
		expectedInterface string
		expectError       bool
	}{
		{
			name: "IPv4 default route with gateway",
			routeMsg: &route.RouteMessage{
				Index: 11,
				Addrs: []route.Addr{
					&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},     // destination
					&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}, // gateway
					&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},     // netmask
					&route.LinkAddr{Index: 11, Name: "en0"},       // interface
				},
			},
			expectedDest:      "0.0.0.0/0",
			expectedGateway:   "192.168.1.1",
			expectedInterface: "en0",
			expectError:       false,
		},
		{
			name: "IPv4 network route with /24 netmask",
			routeMsg: &route.RouteMessage{
				Index: 11,
				Addrs: []route.Addr{
					&route.Inet4Addr{IP: [4]byte{192, 168, 1, 0}},   // destination
					&route.LinkAddr{Index: 11, Name: "en0"},         // gateway (link)
					&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}, // netmask /24
				},
			},
			expectedDest:      "192.168.1.0/24",
			expectedGateway:   "link#11",
			expectedInterface: "en0",
			expectError:       false,
		},
		{
			name: "IPv4 host route with /32 netmask",
			routeMsg: &route.RouteMessage{
				Index: 1,
				Addrs: []route.Addr{
					&route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}},       // destination
					&route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}},       // gateway
					&route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}}, // netmask /32
				},
			},
			expectedDest:      "127.0.0.1/32",
			expectedGateway:   "127.0.0.1",
			expectedInterface: "lo0",
			expectError:       false,
		},
		{
			name: "IPv4 loopback network with /8 netmask",
			routeMsg: &route.RouteMessage{
				Index: 1,
				Addrs: []route.Addr{
					&route.Inet4Addr{IP: [4]byte{127, 0, 0, 0}}, // destination
					&route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}, // gateway
					&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}}, // netmask /8
				},
			},
			expectedDest:      "127.0.0.0/8",
			expectedGateway:   "127.0.0.1",
			expectedInterface: "lo0",
			expectError:       false,
		},
		{
			name: "IPv6 localhost",
			routeMsg: &route.RouteMessage{
				Index: 1,
				Addrs: []route.Addr{
					&route.Inet6Addr{IP: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},                                 // ::1
					&route.Inet6Addr{IP: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},                                 // gateway ::1
					&route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}}, // /128
				},
			},
			expectedDest:      "::1/128",
			expectedGateway:   "::1",
			expectedInterface: "lo0",
			expectError:       false,
		},
		{
			name: "IPv6 with zone ID",
			routeMsg: &route.RouteMessage{
				Index: 11,
				Addrs: []route.Addr{
					&route.Inet6Addr{IP: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, ZoneID: 11}, // fe80::1%11
					&route.LinkAddr{Index: 11, Name: "en0"},
					&route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}}, // /64
				},
			},
			expectedDest:      "fe80::1%en0/64",
			expectedGateway:   "link#11",
			expectedInterface: "en0",
			expectError:       false,
		},
		{
			name: "Route without netmask",
			routeMsg: &route.RouteMessage{
				Index: 11,
				Addrs: []route.Addr{
					&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}},   // destination
					&route.Inet4Addr{IP: [4]byte{192, 168, 1, 254}}, // gateway
				},
			},
			expectedDest:      "192.168.1.1",
			expectedGateway:   "192.168.1.254",
			expectedInterface: "en0",
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, gateway, iface, err := d.parseRouteMessage(tt.routeMsg, interfaceMap)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedDest, dest, "Destination mismatch")
				assert.Equal(t, tt.expectedGateway, gateway, "Gateway mismatch")
				assert.Equal(t, tt.expectedInterface, iface, "Interface mismatch")
			}
		})
	}
}
