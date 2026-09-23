// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenToInternet(t *testing.T) {
	cases := []struct {
		name      string
		action    godo.FirewallRuleAction
		addresses []string
		want      bool
	}{
		{"ipv4 any", "allow", []string{"0.0.0.0/0"}, true},
		{"ipv6 any", "allow", []string{"::/0"}, true},
		{"any among specifics", "allow", []string{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"specific only", "allow", []string{"10.0.0.0/8", "203.0.113.5/32"}, false},
		{"ipv6 specific only", "allow", []string{"2001:db8::/32"}, false},
		{"host address is not a range", "allow", []string{"0.0.0.0"}, false},
		{"empty", "allow", nil, false},
		{"absent action ipv4 any", "", []string{"0.0.0.0/0"}, true},
		{"absent action ipv6 any", "", []string{"::/0"}, true},
		{"uppercase allow", "ALLOW", []string{"0.0.0.0/0"}, true},
		{"deny ipv4 any", "deny", []string{"0.0.0.0/0"}, false},
		{"deny ipv6 any", "deny", []string{"::/0"}, false},
		{"uppercase deny", "DENY", []string{"0.0.0.0/0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, openToInternet(c.action, c.addresses))
		})
	}
}

func TestFirewallRuleActionDecode(t *testing.T) {
	// API-shaped firewall: one rule per action state, including a rule
	// created before deny rules existed that carries no action at all.
	raw := `{
		"id": "fw-1",
		"inbound_rules": [
			{"protocol": "tcp", "ports": "22", "sources": {"addresses": ["0.0.0.0/0"]}, "action": "deny"},
			{"protocol": "tcp", "ports": "443", "sources": {"addresses": ["::/0"]}, "action": "allow"},
			{"protocol": "tcp", "ports": "80", "sources": {"addresses": ["0.0.0.0/0"]}}
		],
		"outbound_rules": [
			{"protocol": "udp", "ports": "53", "destinations": {"addresses": ["0.0.0.0/0"]}, "action": "deny"}
		]
	}`
	var fw godo.Firewall
	require.NoError(t, json.Unmarshal([]byte(raw), &fw))
	require.Len(t, fw.InboundRules, 3)
	require.Len(t, fw.OutboundRules, 1)

	in := fw.InboundRules
	assert.Equal(t, "deny", firewallRuleAction(in[0].Action))
	assert.False(t, openToInternet(in[0].Action, in[0].Sources.Addresses))
	assert.Equal(t, "allow", firewallRuleAction(in[1].Action))
	assert.True(t, openToInternet(in[1].Action, in[1].Sources.Addresses))
	assert.Equal(t, "allow", firewallRuleAction(in[2].Action))
	assert.True(t, openToInternet(in[2].Action, in[2].Sources.Addresses))

	out := fw.OutboundRules[0]
	assert.Equal(t, "deny", firewallRuleAction(out.Action))
	assert.False(t, openToInternet(out.Action, out.Destinations.Addresses))
}
