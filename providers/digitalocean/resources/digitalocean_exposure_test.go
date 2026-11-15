// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
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
		{"ipv4 gap", []string{"0.0.0.0/2", "128.0.0.0/1"}, false},
		{"one ipv4 half", []string{"0.0.0.0/1"}, false},
		{"broad prefix that leaves addresses out", []string{"10.0.0.0/8"}, false},
		{"split ipv6 halves", []string{"::/1", "8000::/1"}, true},
		{"ipv4 and ipv6 halves do not combine", []string{"0.0.0.0/1", "8000::/1"}, false},
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
