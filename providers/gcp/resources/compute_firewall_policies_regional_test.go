// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRegionalScope(t *testing.T) {
	assert.True(t, isRegionalScope("regions/us-central1"))
	assert.False(t, isRegionalScope("global"))
	assert.False(t, isRegionalScope("zones/us-central1-a"))
	assert.False(t, isRegionalScope("regions/"))
}

func TestFirewallPolicyCacheId(t *testing.T) {
	global := "https://www.googleapis.com/compute/v1/projects/p/global/firewallPolicies/fw"
	regional := "https://www.googleapis.com/compute/v1/projects/p/regions/us-central1/firewallPolicies/fw"

	// A global policy keeps the id it has always had.
	assert.Equal(t, "gcloud.compute.firewallPolicy/123", firewallPolicyCacheId("123", global))
	// A regional policy is keyed by its region-carrying self-link, so it can
	// never collide with a global policy, even one with the same numeric id.
	assert.Equal(t, "gcloud.compute.firewallPolicy/"+regional, firewallPolicyCacheId("123", regional))
	assert.NotEqual(t, firewallPolicyCacheId("123", global), firewallPolicyCacheId("123", regional))
}

func TestPolicyAppliesInRegion(t *testing.T) {
	regionUrl := "https://www.googleapis.com/compute/v1/projects/p/regions/us-central1"
	assert.True(t, policyAppliesInRegion("", "europe-west1"), "a global policy applies everywhere")
	assert.True(t, policyAppliesInRegion(regionUrl, "us-central1"))
	assert.False(t, policyAppliesInRegion(regionUrl, "us-central2"))
	assert.True(t, policyAppliesInRegion(regionUrl, ""), "an unknown instance region keeps the policy")
}

func TestRegionFromZoneName(t *testing.T) {
	assert.Equal(t, "us-central1", regionFromZoneName("us-central1-a"))
	assert.Equal(t, "northamerica-northeast2", regionFromZoneName("northamerica-northeast2-c"))
	assert.Equal(t, "", regionFromZoneName(""))
	assert.Equal(t, "", regionFromZoneName("zone"))
	assert.Equal(t, "", regionFromZoneName("us-central1-"))
}
