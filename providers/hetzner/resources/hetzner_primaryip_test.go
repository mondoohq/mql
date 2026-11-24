// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
)

func TestPrimaryIPAssignee(t *testing.T) {
	tests := []struct {
		name       string
		ip         hcloud.PrimaryIP
		wantServer int64
		wantLB     int64
	}{
		// Synthetic: Primary IP held by a server; no live project was checked.
		{"server", hcloud.PrimaryIP{AssigneeType: "server", AssigneeID: 42}, 42, 0},
		// Synthetic: Primary IP held by a load balancer must not read as a server or as unused; no live project was checked.
		{"load balancer", hcloud.PrimaryIP{AssigneeType: "load_balancer", AssigneeID: 7}, 0, 7},
		// Synthetic: unassigned Primary IP as reported since August 2026; no live project was checked.
		{"unassigned", hcloud.PrimaryIP{AssigneeType: "unassigned"}, 0, 0},
		// Synthetic: unassigned Primary IP as reported before August 2026 (type server, no id); no live project was checked.
		{"legacy unassigned", hcloud.PrimaryIP{AssigneeType: "server"}, 0, 0},
		// Synthetic: an assignee type this provider does not model is not guessed; no live project was checked.
		{"unknown type", hcloud.PrimaryIP{AssigneeType: "floating_thing", AssigneeID: 9}, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := tc.ip
			server, lb := primaryIPAssignee(&ip)
			assert.Equal(t, tc.wantServer, server)
			assert.Equal(t, tc.wantLB, lb)
		})
	}
}

func TestLoadBalancerHoldingPrimaryIP(t *testing.T) {
	// Synthetic: two load balancers, one holding Primary IP 42 as its IPv4
	// address and one holding 43 as its IPv6 address; no live project was
	// checked. The API lists a Primary IP's assignee type only as server or
	// unassigned, so a load balancer holding it is found from its own public
	// network.
	v4 := &mqlHetznerLoadBalancer{mqlHetznerLoadBalancerInternal: mqlHetznerLoadBalancerInternal{
		cachePublicNet: hcloud.LoadBalancerPublicNet{IPv4: hcloud.LoadBalancerPublicNetIPv4{ID: 42}},
	}}
	v6 := &mqlHetznerLoadBalancer{mqlHetznerLoadBalancerInternal: mqlHetznerLoadBalancerInternal{
		cachePublicNet: hcloud.LoadBalancerPublicNet{IPv6: hcloud.LoadBalancerPublicNetIPv6{ID: 43}},
	}}
	list := []any{v4, v6}

	assert.Same(t, v4, loadBalancerHoldingPrimaryIP(list, 42))
	assert.Same(t, v6, loadBalancerHoldingPrimaryIP(list, 43))
	assert.Nil(t, loadBalancerHoldingPrimaryIP(list, 44))
	// A system-managed address has no Primary IP ID; 0 must not match it.
	assert.Nil(t, loadBalancerHoldingPrimaryIP([]any{&mqlHetznerLoadBalancer{}}, 0))
}
