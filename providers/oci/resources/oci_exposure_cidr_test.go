// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// TestOciCidrOpensInternet pins the wide-CIDR verdict. An exact comparison
// against the two default routes read a split pair of /1 rules - which together
// span the whole internet - as closed, so these cases are the regression guard
// for that fail-open.
func TestOciCidrOpensInternet(t *testing.T) {
	cases := []struct {
		name string
		cidr string
		want bool
	}{
		{"ipv4 default route", "0.0.0.0/0", true},
		{"ipv6 default route", "::/0", true},
		{"lower half of the internet", "0.0.0.0/1", true},
		{"upper half of the internet", "128.0.0.0/1", true},
		{"ipv6 half", "::/1", true},
		{"a whole public /8", "1.0.0.0/8", true},
		{"non-canonical default route", " 0.0.0.0/0 ", true},

		{"rfc1918 ten", "10.0.0.0/8", false},
		{"rfc1918 172", "172.16.0.0/12", false},
		{"rfc1918 192.168", "192.168.0.0/16", false},
		{"loopback", "127.0.0.0/8", false},
		{"link local", "169.254.0.0/16", false},
		{"ipv6 unique local", "fc00::/7", false},
		{"ipv6 link local", "fe80::/10", false},
		{"a single office address", "203.0.113.10/32", false},
		{"a customer prefix", "203.0.113.0/24", false},
		{"a public /16", "198.51.0.0/16", false},
		{"bare address is not a prefix", "0.0.0.0", false},
		{"empty", "", false},
		{"garbage", "not-a-cidr", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ociCidrOpensInternet(c.cidr); got != c.want {
				t.Errorf("ociCidrOpensInternet(%q) = %v, want %v", c.cidr, got, c.want)
			}
		})
	}
}

// TestOciCidrIsAnyParsesRatherThanCompares guards the narrower predicate: only a
// zero-length prefix admits every address, and it must survive a non-canonical
// spelling.
func TestOciCidrIsAnyParsesRatherThanCompares(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"0.0.0.0/1", false},
		{"1.0.0.0/8", false},
		{"0.0.0.0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := ociCidrIsAny(c.cidr); got != c.want {
			t.Errorf("ociCidrIsAny(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
}

// TestOciAnyPublicIpv6 pins the IPv6 half of the public-address check. A VNIC
// with only an IPv6 global unicast address is internet-facing even though
// publicIp, which is IPv4-only, is empty.
func TestOciAnyPublicIpv6(t *testing.T) {
	cases := []struct {
		name      string
		addresses []any
		want      bool
	}{
		{"no addresses", nil, false},
		{"empty list", []any{}, false},
		{"global unicast", []any{"2001:db8::1"}, true},
		{"global unicast with whitespace", []any{" 2001:db8::1 "}, true},
		{"unique local only", []any{"fd00::1"}, false},
		{"link local only", []any{"fe80::1"}, false},
		{"loopback only", []any{"::1"}, false},
		{"mixed, one global", []any{"fd00::1", "2001:db8::5"}, true},
		{"ipv4 is not counted here", []any{"203.0.113.10"}, false},
		{"non-string entries are skipped", []any{42, nil, "2001:db8::9"}, true},
		{"garbage", []any{"nonsense"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ociAnyPublicIpv6(c.addresses); got != c.want {
				t.Errorf("ociAnyPublicIpv6(%v) = %v, want %v", c.addresses, got, c.want)
			}
		})
	}
}
