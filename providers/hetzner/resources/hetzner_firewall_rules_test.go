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

// cidr is mustCIDR (hetzner_address_test.go) as a value, which is the form
// FirewallRule.SourceIPs takes.
func cidr(t *testing.T, s string) net.IPNet {
	t.Helper()
	return *mustCIDR(t, s)
}

// The firewall rule dicts are the one dict in this provider that was built
// inline rather than through a helper, so they were never run through the llx
// converter the way the deprecation, health-check and nameserver dicts are.
//
// They are also the dicts that matter most: firewallRuleOpenToInternet reads
// them, and the server exposure verdict reads that. A value that fails to
// serialize would take the reachability answer with it.
func TestFirewallRuleDictsSerialize(t *testing.T) {
	port := "80"
	desc := "http from anywhere"

	rules := []hcloud.FirewallRule{
		{
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			SourceIPs:   []net.IPNet{cidr(t, "0.0.0.0/0"), cidr(t, "::/0")},
			Port:        &port,
			Description: &desc,
		},
		{
			// No port and no description: both are *string in the SDK and must
			// stay out of the dict rather than becoming empty strings.
			Direction:      hcloud.FirewallRuleDirectionOut,
			Protocol:       hcloud.FirewallRuleProtocolICMP,
			DestinationIPs: []net.IPNet{cidr(t, "10.0.0.0/8")},
		},
	}

	dicts := firewallRuleDicts(rules)
	require.Len(t, dicts, 2)
	requireDictArraySerializes(t, dicts)

	in, ok := dicts[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "in", in["direction"])
	assert.Equal(t, "tcp", in["protocol"])
	assert.Equal(t, []any{"0.0.0.0/0", "::/0"}, in["sourceIps"])
	assert.Equal(t, "80", in["port"])
	assert.Equal(t, "http from anywhere", in["description"])

	out, ok := dicts[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "out", out["direction"])
	assert.Equal(t, []any{"10.0.0.0/8"}, out["destinationIps"])
	assert.NotContains(t, out, "port", "an unset port must be absent, not an empty string")
	assert.NotContains(t, out, "description", "an unset description must be absent")

	// Empty rules still have to serialize, and as an empty list rather than nil.
	empty := firewallRuleDicts(nil)
	assert.Equal(t, []any{}, empty)
	requireDictArraySerializes(t, empty)
}

// The dicts have to stay readable by the predicate that drives the exposure
// verdict; this is the join the two halves meet at.
func TestFirewallRuleDictsFeedOpenToInternet(t *testing.T) {
	rules := firewallRuleDicts([]hcloud.FirewallRule{{
		Direction: hcloud.FirewallRuleDirectionIn,
		Protocol:  hcloud.FirewallRuleProtocolTCP,
		SourceIPs: []net.IPNet{cidr(t, "0.0.0.0/0")},
	}})
	require.Len(t, rules, 1)

	rule, ok := rules[0].(map[string]any)
	require.True(t, ok)
	assert.True(t, firewallRuleOpenToInternet(rule))

	restricted := firewallRuleDicts([]hcloud.FirewallRule{{
		Direction: hcloud.FirewallRuleDirectionIn,
		Protocol:  hcloud.FirewallRuleProtocolTCP,
		SourceIPs: []net.IPNet{cidr(t, "10.0.0.0/8")},
	}})
	rule, ok = restricted[0].(map[string]any)
	require.True(t, ok)
	assert.False(t, firewallRuleOpenToInternet(rule))
}
