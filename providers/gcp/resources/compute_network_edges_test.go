// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeURLCollection(t *testing.T) {
	const prefix = "https://www.googleapis.com/compute/v1/"
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "zonal instance group",
			url:  prefix + "projects/p/zones/us-central1-a/instanceGroups/ig-1",
			want: "instanceGroups",
		},
		{
			name: "zonal network endpoint group",
			url:  prefix + "projects/p/zones/us-central1-a/networkEndpointGroups/neg-1",
			want: "networkEndpointGroups",
		},
		{
			name: "regional target pool",
			url:  prefix + "projects/p/regions/us-central1/targetPools/tp-1",
			want: "targetPools",
		},
		{
			name: "global target https proxy",
			url:  prefix + "projects/p/global/targetHttpsProxies/proxy-1",
			want: "targetHttpsProxies",
		},
		{
			name: "regional forwarding rule (ILB next hop)",
			url:  prefix + "projects/p/regions/us-central1/forwardingRules/ilb-1",
			want: "forwardingRules",
		},
		{
			name: "compute.googleapis.com host variant",
			url:  "https://compute.googleapis.com/compute/v1/projects/p/global/backendServices/bs-1",
			want: "backendServices",
		},
		{
			name: "trailing slash tolerated",
			url:  prefix + "projects/p/zones/z/instanceGroups/ig-1/",
			want: "instanceGroups",
		},
		{
			name: "surrounding whitespace tolerated",
			url:  "  " + prefix + "projects/p/regions/r/targetPools/tp-1  ",
			want: "targetPools",
		},
		{
			name: "empty url",
			url:  "",
			want: "",
		},
		{
			name: "single segment has no collection",
			url:  "forwardingRules",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeURLCollection(tt.url); got != tt.want {
				t.Errorf("computeURLCollection(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

// TestComputeURLCollectionDispatch documents that the union-typed accessors
// (forwardingRule.target*, backend.instanceGroup/networkEndpointGroup,
// route.nextHopIlbRef) rely on computeURLCollection to route a single raw
// reference to exactly one typed accessor: the accessor whose expected
// collection matches resolves, every sibling returns null.
func TestComputeURLCollectionDispatch(t *testing.T) {
	const prefix = "https://www.googleapis.com/compute/v1/"
	// group URL that a backend's instanceGroup() should claim and
	// networkEndpointGroup() should ignore.
	groupURL := prefix + "projects/p/zones/z/instanceGroups/ig-1"
	if got := computeURLCollection(groupURL); got != "instanceGroups" {
		t.Fatalf("expected instanceGroups dispatch, got %q", got)
	}
	if computeURLCollection(groupURL) == "networkEndpointGroups" {
		t.Fatal("instance group URL must not dispatch to networkEndpointGroup()")
	}

	// forwarding-rule target that only targetHttpsProxy() should claim.
	targetURL := prefix + "projects/p/global/targetHttpsProxies/proxy-1"
	for _, kind := range []string{"targetPools", "targetHttpProxies", "targetTcpProxies", "targetSslProxies"} {
		if computeURLCollection(targetURL) == kind {
			t.Errorf("targetHttpsProxy URL wrongly dispatched to %q", kind)
		}
	}
	if computeURLCollection(targetURL) != "targetHttpsProxies" {
		t.Errorf("targetHttpsProxy URL failed to dispatch to targetHttpsProxies")
	}
}

func TestComputeRefKey(t *testing.T) {
	// Synthetic: the same network written with each host form and none.
	want := "projects/p1/global/networks/n1"
	assert.Equal(t, want, computeRefKey("https://www.googleapis.com/compute/v1/projects/p1/global/networks/n1"))
	assert.Equal(t, want, computeRefKey("https://compute.googleapis.com/compute/v1/projects/p1/global/networks/n1"))
	assert.Equal(t, want, computeRefKey("https://www.googleapis.com/compute/beta/projects/p1/global/networks/n1"))
	assert.Equal(t, want, computeRefKey("projects/p1/global/networks/n1"))
	assert.Equal(t, "", computeRefKey(""))
}

func TestInstancesReferencing(t *testing.T) {
	a := &mqlGcpProjectComputeServiceInstance{}
	a.cacheNetworkUrls = []string{"https://www.googleapis.com/compute/v1/projects/p1/global/networks/n1"}
	// Synthetic: the matching network is on the second NIC, written with the other host.
	b := &mqlGcpProjectComputeServiceInstance{}
	b.cacheNetworkUrls = []string{
		"https://www.googleapis.com/compute/v1/projects/p1/global/networks/other",
		"https://compute.googleapis.com/compute/v1/projects/p1/global/networks/n1",
	}
	// Synthetic: the same network name in another project must not match.
	c := &mqlGcpProjectComputeServiceInstance{}
	c.cacheNetworkUrls = []string{"https://www.googleapis.com/compute/v1/projects/p2/global/networks/n1"}
	d := &mqlGcpProjectComputeServiceInstance{}

	urls := func(i *mqlGcpProjectComputeServiceInstance) []string { return i.cacheNetworkUrls }
	assert.Equal(t, []any{a, b}, instancesReferencing([]any{a, b, c, d}, "projects/p1/global/networks/n1", urls))
	assert.Empty(t, instancesReferencing([]any{a, b, c, d}, "projects/p3/global/networks/n1", urls))
}
