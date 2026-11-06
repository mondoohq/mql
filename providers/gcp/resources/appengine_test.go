// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/appengine/v1"
)

func TestAppEngineVersionVpcAccessDecode(t *testing.T) {
	// Synthetic: the version shape from the App Engine Admin API reference; no
	// live version with direct VPC egress was available to measure.
	raw := `{
		"id": "v1",
		"vpcAccess": {
			"vpcEgress": "ALL_TRAFFIC",
			"networkInterfaces": [
				{"network": "default", "subnet": "apps", "tags": ["web", "egress"]}
			]
		}
	}`
	var v appengine.Version
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	require.NotNil(t, v.VpcAccess)
	assert.Equal(t, "ALL_TRAFFIC", v.VpcAccess.VpcEgress)
	require.Len(t, v.VpcAccess.NetworkInterfaces, 1)
	ni := v.VpcAccess.NetworkInterfaces[0]
	assert.Equal(t, "default", ni.Network)
	assert.Equal(t, "apps", ni.Subnet)
	assert.Equal(t, []string{"web", "egress"}, ni.Tags)
}

func TestAppEngineNetworkPath(t *testing.T) {
	// Synthetic: no network, a short name, and a full path.
	assert.Equal(t, "", appEngineNetworkPath("p", ""))
	assert.Equal(t, "projects/p/global/networks/default", appEngineNetworkPath("p", "default"))
	assert.Equal(t, "projects/host/global/networks/shared", appEngineNetworkPath("p", "projects/host/global/networks/shared"))
}

func TestAppEngineSubnetworkPath(t *testing.T) {
	// Synthetic: a full subnetwork path is kept as given.
	assert.Equal(t, "projects/host/regions/us-east1/subnetworks/s",
		appEngineSubnetworkPath("p", "us-central1", "", "projects/host/regions/us-east1/subnetworks/s"))

	// Synthetic: a short subnetwork name lives in the version's project and region.
	assert.Equal(t, "projects/p/regions/us-central1/subnetworks/apps",
		appEngineSubnetworkPath("p", "us-central1", "default", "apps"))

	// Synthetic: with a Shared VPC network path, a short subnetwork name lives in the host project.
	assert.Equal(t, "projects/host/regions/us-central1/subnetworks/apps",
		appEngineSubnetworkPath("p", "us-central1", "projects/host/global/networks/shared", "apps"))

	// Synthetic: an omitted subnetwork is the one named like the network.
	assert.Equal(t, "projects/p/regions/us-central1/subnetworks/default",
		appEngineSubnetworkPath("p", "us-central1", "default", ""))

	// Synthetic: nothing to resolve, or a short name with no known region.
	assert.Equal(t, "", appEngineSubnetworkPath("p", "us-central1", "", ""))
	assert.Equal(t, "", appEngineSubnetworkPath("p", "", "default", "apps"))
}

func TestAppEngineLocationRegion(t *testing.T) {
	// Synthetic: the two App Engine locations whose names differ from the
	// Compute region, and one that matches it.
	assert.Equal(t, "us-central1", appEngineLocationRegion("us-central"))
	assert.Equal(t, "europe-west1", appEngineLocationRegion("europe-west"))
	assert.Equal(t, "asia-northeast1", appEngineLocationRegion("asia-northeast1"))
	assert.Equal(t, "", appEngineLocationRegion(""))
}
