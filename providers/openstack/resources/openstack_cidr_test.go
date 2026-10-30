// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCidrIsPublic(t *testing.T) {
	tests := []struct {
		cidr string
		want bool
	}{
		// all-addresses
		{"0.0.0.0/0", true},
		{"::/0", true},
		// broad public blocks that the literal-/0 check used to miss
		{"0.0.0.0/1", true},
		{"128.0.0.0/1", true},
		{"13.0.0.0/8", true},
		// private / reserved ranges are not internet exposure
		{"10.0.0.0/8", false},
		{"172.16.0.0/12", false},
		{"192.168.0.0/16", false},
		{"127.0.0.0/8", false},
		{"169.254.0.0/16", false},
		{"100.64.0.0/10", false},
		{"fc00::/7", false},
		// specific or narrow ranges are scoped, not "the internet"
		{"203.0.113.5/32", false},
		{"52.94.0.0/16", false},
		{"2600:1f00::/24", true},
		{"2001:db8::/48", false},
		// malformed / empty
		{"", false},
		{"not-a-cidr", false},
		{"0.0.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			assert.Equal(t, tt.want, cidrIsPublic(tt.cidr))
		})
	}
}

func TestAddressIsPublic(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		// CIDR members follow the same rules as a rule's remote IP prefix
		{"all addresses", "0.0.0.0/0", true},
		{"all addresses v6", "::/0", true},
		{"private block", "10.0.0.0/8", false},
		{"single host", "203.0.113.5/32", false},

		// ranges: broad enough to count, and outside private space
		{"range spanning a full /8", "13.0.0.0-13.255.255.255", true},
		{"range spanning more than a /8", "13.0.0.0-15.255.255.255", true},
		{"range one short of a /8", "13.0.0.1-13.255.255.255", false},
		{"private range spanning a /8", "10.0.0.0-10.255.255.255", false},
		{"loopback range", "127.0.0.0-127.255.255.255", false},
		{"narrow public range", "203.0.113.10-203.0.113.20", false},
		{"broad v6 range", "2600:1f00::-2600:1fff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"narrow v6 range", "2600:1f00::1-2600:1f00::ff", false},

		// a range that spans out of private space into public is not contained
		// by any single reserved block, so it counts
		{"range crossing out of private space", "10.0.0.0-13.255.255.255", true},

		// whitespace is tolerated; the members come from a JSON list
		{"padded range", " 13.0.0.0 - 13.255.255.255 ", true},

		// malformed and degenerate inputs
		{"empty", "", false},
		{"bare address", "203.0.113.5", false},
		{"reversed range", "13.255.255.255-13.0.0.0", false},
		{"mixed family range", "13.0.0.0-2600:1f00::", false},
		{"garbage range", "not-an-ip-at-all", false},
		{"half a range", "13.0.0.0-", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, addressIsPublic(tt.addr))
		})
	}
}

func TestAnyCidrPublic(t *testing.T) {
	assert.True(t, anyCidrPublic([]any{"10.0.0.0/8", "0.0.0.0/1"}))
	assert.False(t, anyCidrPublic([]any{"10.0.0.0/8", "192.168.1.0/24"}))
	assert.False(t, anyCidrPublic([]any{}))
	assert.False(t, anyCidrPublic([]any{42, "10.0.0.0/8"}))
}
