// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"net/http"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestParseFirewallPortRange(t *testing.T) {
	tests := []struct {
		in         string
		start, end int64
		ok         bool
	}{
		{in: "22", start: 22, end: 22, ok: true},
		{in: "1024-5000", start: 1024, end: 5000, ok: true},
		{in: "any", start: 1, end: 65535, ok: true},
		{in: "ANY", start: 1, end: 65535, ok: true},
		{in: " 80 ", start: 80, end: 80, ok: true},
		{in: "", ok: false},
		{in: "http", ok: false},
		{in: "80-", ok: false},
		{in: "5000-1024", ok: false},
		{in: "0", ok: false},
		{in: "1-70000", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			start, end, ok := parseFirewallPortRange(tt.in)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.start, start)
				assert.Equal(t, tt.end, end)
			}
		})
	}
}

// The typed rule's openToInternet and the server exposure verdict are computed
// by two functions, one on the SDK rule and one on its dict form. They must
// never disagree, or a rule the exposure reports as open would read closed on
// the firewall itself.
func TestFirewallRuleAdmitsAnySourceAgreesWithExposure(t *testing.T) {
	tests := []struct {
		name string
		rule hcloud.FirewallRule
		want bool
	}{
		{
			name: "inbound from any IPv4",
			rule: hcloud.FirewallRule{Direction: hcloud.FirewallRuleDirectionIn, SourceIPs: []net.IPNet{cidr(t, "0.0.0.0/0")}},
			want: true,
		},
		{
			name: "inbound from any IPv6",
			rule: hcloud.FirewallRule{Direction: hcloud.FirewallRuleDirectionIn, SourceIPs: []net.IPNet{cidr(t, "10.0.0.0/8"), cidr(t, "::/0")}},
			want: true,
		},
		{
			name: "inbound from a private range",
			rule: hcloud.FirewallRule{Direction: hcloud.FirewallRuleDirectionIn, SourceIPs: []net.IPNet{cidr(t, "10.0.0.0/8")}},
			want: false,
		},
		{
			name: "inbound from a single host",
			rule: hcloud.FirewallRule{Direction: hcloud.FirewallRuleDirectionIn, SourceIPs: []net.IPNet{cidr(t, "0.0.0.0/32")}},
			want: false,
		},
		{
			name: "outbound to anywhere",
			rule: hcloud.FirewallRule{Direction: hcloud.FirewallRuleDirectionOut, DestinationIPs: []net.IPNet{cidr(t, "0.0.0.0/0")}, SourceIPs: []net.IPNet{cidr(t, "0.0.0.0/0")}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firewallRuleAdmitsAnySource(tt.rule))
			dict, ok := firewallRuleDicts([]hcloud.FirewallRule{tt.rule})[0].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, tt.want, firewallRuleOpenToInternet(dict))
		})
	}
}

const firewallWithRulesBody = `{"firewall":{"id":7,"name":"web","created":"2026-01-01T00:00:00+00:00",
"labels":{},"applied_to":[],"rules":[
{"direction":"in","protocol":"tcp","port":"20-30","source_ips":["0.0.0.0/0","::/0"],"destination_ips":[],"description":"ssh range"},
{"direction":"out","protocol":"tcp","port":"any","source_ips":[],"destination_ips":["0.0.0.0/0"]},
{"direction":"in","protocol":"icmp","source_ips":["10.0.0.0/8"],"destination_ips":[]},
{"direction":"in","protocol":"tcp","port":"20-30","source_ips":["0.0.0.0/0","::/0"],"destination_ips":[],"description":"ssh range"}
]}}`

func TestFirewallRulesSplitByDirection(t *testing.T) {
	runtime := initRuntime(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(firewallWithRulesBody))
	})
	_, res, err := initHetznerFirewall(runtime, map[string]*llx.RawData{"id": llx.IntData(7)})
	require.NoError(t, err)
	fw := res.(*mqlHetznerFirewall)

	inbound, err := fw.inboundRules()
	require.NoError(t, err)
	require.Len(t, inbound, 3, "two identical inbound rules must stay two rules")

	outbound, err := fw.outboundRules()
	require.NoError(t, err)
	require.Len(t, outbound, 1)

	ssh := inbound[0].(*mqlHetznerFirewallRule)
	assert.Equal(t, "in", ssh.Direction.Data)
	assert.Equal(t, "20-30", ssh.Port.Data)
	assert.Equal(t, int64(20), ssh.PortStart.Data)
	assert.Equal(t, int64(30), ssh.PortEnd.Data)
	assert.True(t, ssh.OpenToInternet.Data)
	assert.Equal(t, "ssh range", ssh.Description.Data)
	assert.Equal(t, []any{"0.0.0.0/0", "::/0"}, ssh.SourceIps.Data)
	parent, err := ssh.firewall()
	require.NoError(t, err)
	assert.Same(t, fw, parent)

	icmp := inbound[1].(*mqlHetznerFirewallRule)
	assert.Equal(t, "icmp", icmp.Protocol.Data)
	assert.True(t, icmp.Port.IsNull(), "icmp has no port")
	assert.True(t, icmp.PortStart.IsNull())
	assert.True(t, icmp.PortEnd.IsNull())
	assert.True(t, icmp.Description.IsNull(), "an unset description is null, not empty")
	assert.False(t, icmp.OpenToInternet.Data)

	dup := inbound[2].(*mqlHetznerFirewallRule)
	assert.NotSame(t, ssh, dup, "identical rules must not collapse onto one cached resource")

	egress := outbound[0].(*mqlHetznerFirewallRule)
	assert.Equal(t, int64(1), egress.PortStart.Data)
	assert.Equal(t, int64(65535), egress.PortEnd.Data)
	assert.False(t, egress.OpenToInternet.Data, "an outbound rule never opens ingress")

	ids := map[string]struct{}{}
	for _, r := range append(append([]any{}, inbound...), outbound...) {
		ids[r.(*mqlHetznerFirewallRule).MqlID()] = struct{}{}
	}
	assert.Len(t, ids, 4)
}
