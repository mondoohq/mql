// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/compute/v1"
)

func TestParseNetworkURL(t *testing.T) {
	tests := []struct {
		name             string
		url              string
		project, network string
		ok               bool
	}{
		{
			name: "www.googleapis.com form",
			url:  "https://www.googleapis.com/compute/v1/projects/proj-1/global/networks/net-1",
			// Both host forms appear in the same API responses depending on the
			// field, so a matcher that handles only one silently drops rules.
			project: "proj-1", network: "net-1", ok: true,
		},
		{
			name:    "compute.googleapis.com form",
			url:     "https://compute.googleapis.com/compute/v1/projects/proj-2/global/networks/net-2",
			project: "proj-2", network: "net-2", ok: true,
		},
		{
			name: "empty url",
			url:  "",
		},
		{
			// A subnetwork self-link must not be mistaken for a network one.
			name: "subnetwork url is rejected",
			url:  "https://www.googleapis.com/compute/v1/projects/proj-1/regions/us-central1/subnetworks/sub-1",
		},
		{
			name: "truncated url",
			url:  "https://www.googleapis.com/compute/v1/projects/proj-1/global",
		},
		{
			name: "unrelated url",
			url:  "not-a-url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, network, ok := parseNetworkURL(tt.url)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.project, project)
			assert.Equal(t, tt.network, network)
		})
	}
}

func TestFirewallAllowedProtocolPorts(t *testing.T) {
	got := firewallAllowedProtocolPorts([]*compute.FirewallAllowed{
		{IPProtocol: "tcp", Ports: []string{"22", "8000-8080"}},
		{IPProtocol: "icmp"},
	})

	assert.Equal(t, map[string]any{
		"tcp": []any{"22", "8000-8080"},
		// icmp carries no ports; the empty list must still be present so the
		// protocol itself is queryable, rather than the key vanishing.
		"icmp": []any{},
	}, got)
}

func TestFirewallDeniedProtocolPorts(t *testing.T) {
	got := firewallDeniedProtocolPorts([]*compute.FirewallDenied{
		{IPProtocol: "udp", Ports: []string{"53"}},
	})
	assert.Equal(t, map[string]any{"udp": []any{"53"}}, got)
}

func TestLayer4ProtocolPorts(t *testing.T) {
	got := layer4ProtocolPorts([]*compute.FirewallPolicyRuleMatcherLayer4Config{
		{IpProtocol: "tcp", Ports: []string{"443"}},
	})
	assert.Equal(t, map[string]any{"tcp": []any{"443"}}, got)
}

func TestProtocolPortsMergesRepeatedProtocol(t *testing.T) {
	// A protocol is not documented to repeat within one rule, but if it does the
	// ports must merge rather than the second entry overwriting the first.
	got := protocolPorts([]protocolPort{
		{protocol: "tcp", ports: []string{"22"}},
		{protocol: "tcp", ports: []string{"443"}},
	})
	assert.Equal(t, map[string]any{"tcp": []any{"22", "443"}}, got)
}

func TestProtocolPortsSkipsNilAndEmpty(t *testing.T) {
	// A nil SDK entry must not panic, and an entry with no protocol has nothing
	// to key on so it is dropped rather than creating an "" bucket.
	assert.Equal(t, map[string]any{}, firewallAllowedProtocolPorts([]*compute.FirewallAllowed{nil}))
	assert.Equal(t, map[string]any{}, protocolPorts([]protocolPort{{protocol: "", ports: []string{"22"}}}))
	assert.Equal(t, map[string]any{}, protocolPorts(nil))
}
