// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAnyAddress(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"0.0.0.0", true},
		{"::", true},
		{" 0.0.0.0/0 ", true}, // surrounding whitespace tolerated
		{"10.0.0.0/8", false},
		{"203.0.113.5/32", false},
		{"2001:db8::/32", false},
		{"", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, isAnyAddress(c.cidr), "isAnyAddress(%q)", c.cidr)
	}
}

func TestAddressesCoverInternet(t *testing.T) {
	cases := []struct {
		name      string
		addresses []string
		want      bool
	}{
		{"empty", nil, false},
		{"ipv4 any", []string{"0.0.0.0/0"}, true},
		{"ipv6 any", []string{"::/0"}, true},
		{"ipv6 any, non-canonical", []string{"::0/0"}, true},
		{"split ipv4 halves", []string{"128.0.0.0/1", "0.0.0.0/1"}, true},
		{"split ipv4 quarters with overlap", []string{"0.0.0.0/2", "64.0.0.0/2", "0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"}, true},
		{"ipv4 gap still leaves half the internet", []string{"0.0.0.0/2", "128.0.0.0/1"}, true},
		{"one ipv4 half", []string{"0.0.0.0/1"}, true},
		{"broad prefix that leaves addresses out", []string{"10.0.0.0/8"}, false},
		{"split ipv6 halves", []string{"::/1", "8000::/1"}, true},
		{"ipv6 half outside 2000::/3", []string{"8000::/1"}, false},
		{"ipv6 global unicast", []string{"2000::/3"}, true},
		{"256 /8s cover all of ipv4", v4Slash8s(0, 255, 1), true},
		{"448 /9s cover 0.0.0.0 through 223.255.255.255", v4Slash9s(0, 223), true},
		{"128 /9s span 0.0.0.0/2", v4Slash9s(0, 63), true},
		{"odd /8s cover half the routable space with no aligned /7", v4Slash8s(1, 223, 2), true},
		{"odd /8s one short of half", v4Slash8s(1, 221, 2), false},
		{"two /8s straddling a /7 boundary", []string{"1.0.0.0/8", "2.0.0.0/8"}, false},
		{"two /8s forming an aligned /7", []string{"2.0.0.0/8", "3.0.0.0/8"}, true},
		{"/8s inside multicast and reserved", v4Slash8s(224, 255, 1), false},
		{"private ranges", []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, false},
		{"mixed families, ipv4 open", append(v4Slash8s(0, 255, 1), "2001:db8::/32"), true},
		{"mixed families, ipv6 open", append(v4Slash8s(1, 221, 2), "2000::/4", "3000::/4"), true},
		{"mixed families, both with gaps", append(v4Slash8s(1, 221, 2), "2000::/12", "2020::/12"), false},
		{"ipv6 /12s forming an aligned /11", []string{"2000::/12", "2010::/12"}, true},
		{"ipv6 /12s with a gap", []string{"2000::/12", "2020::/12"}, false},
		{"ipv6 every other /12 covers half of 2000::/3", v6OddSlash12s(), true},
		{"ipv6 hosts are ignored", []string{"2001:db8::1/128", "2001:db8::2/128"}, false},
		{"load balancer cidr prefixes on many /8s", prefixed("cidr:", v4Slash8s(0, 255, 1)), true},
		{"ipv4-mapped any", []string{"::ffff:0.0.0.0/96"}, true},
		{"load balancer cidr prefix", []string{"cidr:0.0.0.0/0"}, true},
		{"load balancer split cidr prefixes", []string{"cidr:0.0.0.0/1", "cidr:128.0.0.0/1"}, true},
		{"load balancer ip prefix", []string{"ip:203.0.113.10"}, false},
		{"host address", []string{"203.0.113.10"}, false},
		{"unspecified address", []string{"0.0.0.0"}, true},
		{"padded", []string{" 0.0.0.0/0 "}, true},
		{"unparseable counts as open", []string{"not-an-address"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, addressesCoverInternet(c.addresses))
		})
	}
}

// v4Slash8s returns first.0.0.0/8 through last.0.0.0/8, stepping by step.
func v4Slash8s(first, last, step int) []string {
	out := []string{}
	for i := first; i <= last; i += step {
		out = append(out, fmt.Sprintf("%d.0.0.0/8", i))
	}
	return out
}

// v4Slash9s returns the two /9s of every /8 from first through last.
func v4Slash9s(first, last int) []string {
	out := []string{}
	for i := first; i <= last; i++ {
		out = append(out, fmt.Sprintf("%d.0.0.0/9", i), fmt.Sprintf("%d.128.0.0/9", i))
	}
	return out
}

// v6OddSlash12s returns every other /12 inside 2000::/3, 256 in all.
func v6OddSlash12s() []string {
	out := []string{}
	for i := 1; i < 512; i += 2 {
		out = append(out, fmt.Sprintf("%x::/12", 0x2000+i<<4))
	}
	return out
}

func prefixed(prefix string, list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, prefix+s)
	}
	return out
}

func TestMergeSpans(t *testing.T) {
	got := mergeSpans([]addrSpan{{10, 20}, {0, 4}, {21, 30}, {5, 5}, {40, 50}, {45, 46}})
	assert.Equal(t, []addrSpan{{0, 5}, {10, 30}, {40, 50}}, got)
	full := mergeSpans([]addrSpan{{0, ^uint64(0)}, {7, 9}})
	assert.Equal(t, []addrSpan{{0, ^uint64(0)}}, full)
}

func TestDatabaseRuleOpensToInternet(t *testing.T) {
	cases := []struct {
		name     string
		ruleType string
		value    string
		want     bool
	}{
		{"ip_addr any v4", "ip_addr", "0.0.0.0/0", true},
		{"ip_addr any v6", "ip_addr", "::/0", true},
		{"ip_addr specific", "ip_addr", "203.0.113.0/24", false},
		{"droplet any-looking value", "droplet", "0.0.0.0/0", false}, // type scopes to a droplet, not a CIDR
		{"tag", "tag", "web", false},
		{"k8s", "k8s", "cluster-uuid", false},
		{"app", "app", "app-uuid", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, databaseRuleOpensToInternet(c.ruleType, c.value))
		})
	}
}

func TestDatabaseTrustedSourcesAllowAny(t *testing.T) {
	cases := []struct {
		name  string
		rules []any
		want  bool
	}{
		{"no rules means open", nil, true},
		{"empty rules means open", []any{}, true},
		{
			"only specific ip rules",
			[]any{
				map[string]any{"type": "ip_addr", "value": "203.0.113.10/32"},
				map[string]any{"type": "droplet", "value": "12345"},
			},
			false,
		},
		{
			"contains any-address ip rule",
			[]any{
				map[string]any{"type": "ip_addr", "value": "203.0.113.10/32"},
				map[string]any{"type": "ip_addr", "value": "0.0.0.0/0"},
			},
			true,
		},
		{
			"contains any-address ipv6 rule",
			[]any{
				map[string]any{"type": "ip_addr", "value": "::/0"},
			},
			true,
		},
		{
			"ip rules that together cover the internet",
			[]any{
				map[string]any{"type": "ip_addr", "value": "0.0.0.0/1"},
				map[string]any{"type": "ip_addr", "value": "128.0.0.0/1"},
			},
			true,
		},
		{
			"many narrow ip rules that together cover the internet",
			func() []any {
				out := []any{}
				for _, v := range v4Slash9s(0, 223) {
					out = append(out, map[string]any{"type": "ip_addr", "value": v})
				}
				return out
			}(),
			true,
		},
		{
			"only resource-scoped rules",
			[]any{
				map[string]any{"type": "tag", "value": "web"},
				map[string]any{"type": "k8s", "value": "cluster-uuid"},
			},
			false,
		},
		{
			"malformed entry ignored",
			[]any{
				"not-a-map",
				map[string]any{"type": "ip_addr", "value": "10.0.0.0/8"},
			},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, databaseTrustedSourcesAllowAny(c.rules))
		})
	}
}

func TestLoadBalancerFirewallAllowsAny(t *testing.T) {
	cases := []struct {
		name  string
		allow []any
		want  bool
	}{
		{"empty allow list permits all sources", nil, true},
		{"empty slice permits all sources", []any{}, true},
		{"specific allow CIDRs only", []any{"203.0.113.0/24", "198.51.100.7/32"}, false},
		{"allow includes any-address v4", []any{"203.0.113.0/24", "0.0.0.0/0"}, true},
		{"allow includes any-address v6", []any{"::/0"}, true},
		{"non-string entry ignored", []any{42, "10.0.0.0/8"}, false},
		{"cidr-prefixed any-address", []any{"cidr:0.0.0.0/0"}, true},
		{"cidr-prefixed split halves", []any{"cidr:0.0.0.0/1", "cidr:128.0.0.0/1"}, true},
		{"ip-prefixed host only", []any{"ip:198.51.100.7"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, loadBalancerFirewallAllowsAny(c.allow))
		})
	}
}
