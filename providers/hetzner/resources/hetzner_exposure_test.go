// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirewallRuleOpenToInternet(t *testing.T) {
	tests := []struct {
		name string
		rule map[string]any
		want bool
	}{
		{"inbound any ipv4", map[string]any{"direction": "in", "sourceIps": []any{"0.0.0.0/0"}}, true},
		{"inbound any ipv6", map[string]any{"direction": "in", "sourceIps": []any{"::/0"}}, true},
		{"inbound mixed with any", map[string]any{"direction": "in", "sourceIps": []any{"10.0.0.0/8", "0.0.0.0/0"}}, true},
		{"inbound scoped source", map[string]any{"direction": "in", "sourceIps": []any{"203.0.113.0/24"}}, false},
		{"inbound ipv4 split in halves", map[string]any{"direction": "in", "sourceIps": []any{"0.0.0.0/1", "128.0.0.0/1"}}, true},
		{"inbound ipv6 global unicast", map[string]any{"direction": "in", "sourceIps": []any{"2000::/3"}}, true},
		{"inbound private ipv4", map[string]any{"direction": "in", "sourceIps": []any{"10.0.0.0/8"}}, false},
		{"inbound host bits set", map[string]any{"direction": "in", "sourceIps": []any{"10.0.0.1/0"}}, true},
		{"inbound unparseable source", map[string]any{"direction": "in", "sourceIps": []any{"not-a-cidr"}}, false},
		{"outbound any", map[string]any{"direction": "out", "sourceIps": []any{"0.0.0.0/0"}}, false},
		{"no sources", map[string]any{"direction": "in"}, false},
		{"empty", map[string]any{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firewallRuleOpenToInternet(tt.rule))
		})
	}
}

func TestSourcesAdmitInternetSinglePrefix(t *testing.T) {
	tests := []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"0.0.0.0/1", true},
		{"128.0.0.0/1", true},
		{"192.0.0.0/2", true},
		{"0.0.0.0/7", true},
		{"10.0.0.0/8", false},
		{"11.0.0.0/8", false},
		{"203.0.113.0/24", false},
		{"224.0.0.0/3", false},
		{"240.0.0.0/4", false},
		{"::/0", true},
		{"::/2", true},
		{"2000::/3", true},
		{"2a00::/8", true},
		{"2a00::/12", false},
		{"2001:db8::/32", false},
		{"fc00::/7", false},
		{"fe80::/10", false},
		{"4000::/2", false},
		// net.ParseCIDR masks host bits and accepts any IPv6 spelling, so
		// non-canonical forms resolve to the same network.
		{"10.0.0.1/0", true},
		{"255.0.0.0/0", true},
		{"0::/0", true},
		{"2000:0::/3", true},
		{"2A01:4F8::/8", true},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			_, n, err := net.ParseCIDR(tt.cidr)
			require.NoError(t, err)
			assert.Equal(t, tt.want, sourcesAdmitInternet([]net.IPNet{*n}))
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

func TestSourcesAdmitInternetUnion(t *testing.T) {
	tests := []struct {
		name    string
		sources []string
		want    bool
	}{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets := make([]net.IPNet, 0, len(tt.sources))
			dict := make([]any, 0, len(tt.sources))
			for _, s := range tt.sources {
				_, n, err := net.ParseCIDR(s)
				require.NoError(t, err)
				nets = append(nets, *n)
				dict = append(dict, s)
			}
			assert.Equal(t, tt.want, sourcesAdmitInternet(nets))
			// The typed rule and its dict form must agree.
			assert.Equal(t, tt.want, firewallRuleAdmitsAnySource(hcloud.FirewallRule{Direction: hcloud.FirewallRuleDirectionIn, SourceIPs: nets}))
			assert.Equal(t, tt.want, firewallRuleOpenToInternet(map[string]any{"direction": "in", "sourceIps": dict}))
		})
	}
}

func TestMergeSpans(t *testing.T) {
	got := mergeSpans([]addrSpan{{10, 20}, {0, 4}, {21, 30}, {5, 5}, {40, 50}, {45, 46}})
	assert.Equal(t, []addrSpan{{0, 5}, {10, 30}, {40, 50}}, got)
	full := mergeSpans([]addrSpan{{0, ^uint64(0)}, {7, 9}})
	assert.Equal(t, []addrSpan{{0, ^uint64(0)}}, full)
}

func TestRulesRestrictEgress(t *testing.T) {
	inbound := map[string]any{"direction": "in", "sourceIps": []any{"0.0.0.0/0"}}
	outbound := map[string]any{"direction": "out", "destinationIps": []any{"10.0.0.0/8"}}
	tests := []struct {
		name  string
		rules []any
		want  bool
	}{
		{"no rules at all", nil, false},
		{"inbound only", []any{inbound}, false},
		{"outbound only", []any{outbound}, true},
		{"mixed", []any{inbound, outbound}, true},
		{"malformed entries ignored", []any{"not-a-rule", 42}, false},
		{"malformed alongside outbound", []any{"not-a-rule", outbound}, true},
		{"direction wrong type", []any{map[string]any{"direction": 7}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rulesRestrictEgress(tt.rules))
		})
	}
}

func TestServerFirewallIngress(t *testing.T) {
	open := map[string]any{"direction": "in", "sourceIps": []any{"0.0.0.0/0"}}
	scoped := map[string]any{"direction": "in", "sourceIps": []any{"203.0.113.0/24"}}
	applied := string(hcloud.FirewallStatusApplied)
	pending := string(hcloud.FirewallStatusPending)

	tests := []struct {
		name          string
		bindings      []firewallBindingRules
		wantIngress   bool
		wantOpenRules int
	}{
		{"no bindings admits ingress", nil, true, 0},
		{
			"applied binding with scoped rule blocks ingress",
			[]firewallBindingRules{{status: applied, rules: []any{scoped}}},
			false, 0,
		},
		{
			"applied binding with open rule admits ingress",
			[]firewallBindingRules{{status: applied, rules: []any{open}}},
			true, 1,
		},
		{
			// The regression this guards: a pending binding is not enforcing, so
			// the server is still open even though a firewall is attached.
			"only pending binding admits ingress",
			[]firewallBindingRules{{status: pending, rules: []any{scoped}}},
			true, 0,
		},
		{
			"pending binding's open rule is not reported",
			[]firewallBindingRules{{status: pending, rules: []any{open}}},
			true, 0,
		},
		{
			"applied scoped alongside pending stays closed",
			[]firewallBindingRules{
				{status: applied, rules: []any{scoped}},
				{status: pending, rules: []any{open}},
			},
			false, 0,
		},
		{
			"open rules collected across applied bindings",
			[]firewallBindingRules{
				{status: applied, rules: []any{open}},
				{status: applied, rules: []any{open, scoped}},
			},
			true, 2,
		},
		{
			"applied binding with no rules blocks ingress",
			[]firewallBindingRules{{status: applied}},
			false, 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIngress, gotRules := serverFirewallIngress(tt.bindings)
			assert.Equal(t, tt.wantIngress, gotIngress)
			assert.Len(t, gotRules, tt.wantOpenRules)
		})
	}
}

func TestLoadBalancerHasPublicIp(t *testing.T) {
	ipv4 := net.ParseIP("203.0.113.10")
	ipv6 := net.ParseIP("2001:db8::1")
	tests := []struct {
		name string
		pn   hcloud.LoadBalancerPublicNet
		want bool
	}{
		{"disabled with ipv4", hcloud.LoadBalancerPublicNet{Enabled: false, IPv4: hcloud.LoadBalancerPublicNetIPv4{IP: ipv4}}, false},
		{"enabled with ipv4", hcloud.LoadBalancerPublicNet{Enabled: true, IPv4: hcloud.LoadBalancerPublicNetIPv4{IP: ipv4}}, true},
		{"enabled with ipv6 only", hcloud.LoadBalancerPublicNet{Enabled: true, IPv6: hcloud.LoadBalancerPublicNetIPv6{IP: ipv6}}, true},
		{"enabled no ip", hcloud.LoadBalancerPublicNet{Enabled: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, loadBalancerHasPublicIp(tt.pn))
		})
	}
}

func TestLoadBalancerServiceDicts(t *testing.T) {
	got := loadBalancerServiceDicts([]hcloud.LoadBalancerService{
		{Protocol: hcloud.LoadBalancerServiceProtocolHTTPS, ListenPort: 443, DestinationPort: 8443},
	})
	assert.Len(t, got, 1)
	d := got[0].(map[string]any)
	assert.Equal(t, "https", d["protocol"])
	assert.Equal(t, int64(443), d["listenPort"])
	assert.Equal(t, int64(8443), d["destinationPort"])

	assert.Empty(t, loadBalancerServiceDicts(nil))
}
