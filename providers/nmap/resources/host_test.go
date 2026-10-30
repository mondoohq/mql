// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/assert"
)

func TestHostScanName(t *testing.T) {
	tests := []struct {
		name      string
		addresses []nmap.Address
		expected  string
	}{
		{
			name:      "no addresses",
			addresses: nil,
			expected:  "",
		},
		{
			name:      "single ipv4",
			addresses: []nmap.Address{{Addr: "192.0.2.10", AddrType: "ipv4"}},
			expected:  "192.0.2.10",
		},
		{
			// A local-segment host commonly reports both an IPv4 and a MAC
			// address. We must return the scannable IPv4, never a joined
			// string or the MAC.
			name: "ipv4 plus mac prefers ipv4",
			addresses: []nmap.Address{
				{Addr: "192.0.2.10", AddrType: "ipv4"},
				{Addr: "AA:BB:CC:DD:EE:FF", AddrType: "mac", Vendor: "Acme"},
			},
			expected: "192.0.2.10",
		},
		{
			name: "mac listed first still prefers ipv4",
			addresses: []nmap.Address{
				{Addr: "AA:BB:CC:DD:EE:FF", AddrType: "mac"},
				{Addr: "192.0.2.10", AddrType: "ipv4"},
			},
			expected: "192.0.2.10",
		},
		{
			name: "no ipv4 falls back to ipv6",
			addresses: []nmap.Address{
				{Addr: "AA:BB:CC:DD:EE:FF", AddrType: "mac"},
				{Addr: "2001:db8::1", AddrType: "ipv6"},
			},
			expected: "2001:db8::1",
		},
		{
			name: "only mac falls back to the mac",
			addresses: []nmap.Address{
				{Addr: "AA:BB:CC:DD:EE:FF", AddrType: "mac"},
			},
			expected: "AA:BB:CC:DD:EE:FF",
		},
		{
			name: "skips empty addresses",
			addresses: []nmap.Address{
				{Addr: "", AddrType: "ipv4"},
				{Addr: "2001:db8::1", AddrType: "ipv6"},
			},
			expected: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hostScanName(tt.addresses))
		})
	}
}
