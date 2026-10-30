// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/analytics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeAnalyticsInstance decodes one item of a ListAnalyticsInstances
// response, so the polymorphic networkEndpointDetails goes through the SDK's
// own unmarshalling, as it does on a live call.
func decodeAnalyticsInstance(t *testing.T, endpoint string) analytics.AnalyticsInstanceSummary {
	t.Helper()
	body := `{"id": "ocid1.analyticsinstance.oc1..x", "name": "oac", "compartmentId": "ocid1.compartment.oc1..c",
		"lifecycleState": "ACTIVE", "featureSet": "ENTERPRISE_ANALYTICS",
		"capacity": {"capacityType": "OLPU_COUNT", "capacityValue": 2},
		"timeCreated": "2026-10-01T00:00:00.000Z"`
	if endpoint != "" {
		body += `, "networkEndpointDetails": ` + endpoint
	}
	body += `}`
	var inst analytics.AnalyticsInstanceSummary
	require.NoError(t, json.Unmarshal([]byte(body), &inst))
	return inst
}

func TestAnalyticsEndpoint(t *testing.T) {
	t.Run("a private endpoint is not reachable from the internet", func(t *testing.T) {
		inst := decodeAnalyticsInstance(t, `{"networkEndpointType": "PRIVATE", "vcnId": "ocid1.vcn.oc1..v",
			"subnetId": "ocid1.subnet.oc1..s", "networkSecurityGroupIds": ["ocid1.networksecuritygroup.oc1..n"]}`)
		got := analyticsEndpointOf(inst.NetworkEndpointDetails)
		assert.Equal(t, "PRIVATE", got.endpointType)
		assert.Equal(t, "ocid1.vcn.oc1..v", got.vcnID)
		assert.Equal(t, "ocid1.subnet.oc1..s", got.subnetID)
		assert.Equal(t, []string{"ocid1.networksecuritygroup.oc1..n"}, got.nsgIDs)
		assert.Empty(t, got.whitelistedIps)
		assert.False(t, got.internetReachable)
	})

	t.Run("a public endpoint without access control rules is open", func(t *testing.T) {
		inst := decodeAnalyticsInstance(t, `{"networkEndpointType": "PUBLIC"}`)
		got := analyticsEndpointOf(inst.NetworkEndpointDetails)
		assert.Equal(t, "PUBLIC", got.endpointType)
		assert.True(t, got.internetReachable)
	})

	t.Run("access control rules restrict a public endpoint", func(t *testing.T) {
		inst := decodeAnalyticsInstance(t, `{"networkEndpointType": "PUBLIC", "whitelistedIps": ["203.0.113.0/24"],
			"whitelistedVcns": [{"id": "ocid1.vcn.oc1..v", "whitelistedIps": ["10.0.0.0/16"]}],
			"whitelistedServices": ["ALL_SERVICES"]}`)
		got := analyticsEndpointOf(inst.NetworkEndpointDetails)
		assert.Equal(t, []any{"203.0.113.0/24"}, got.whitelistedIps)
		assert.Equal(t, []any{map[string]any{"id": "ocid1.vcn.oc1..v", "whitelistedIps": []any{"10.0.0.0/16"}}}, got.whitelistedVcns)
		assert.Equal(t, []any{"ALL_SERVICES"}, got.whitelistedServices)
		assert.False(t, got.internetReachable)
	})

	t.Run("a VCN or an Oracle service alone restricts a public endpoint", func(t *testing.T) {
		for _, endpoint := range []string{
			`{"networkEndpointType": "PUBLIC", "whitelistedVcns": [{"id": "ocid1.vcn.oc1..v"}]}`,
			`{"networkEndpointType": "PUBLIC", "whitelistedServices": ["ALL_SERVICES"]}`,
		} {
			got := analyticsEndpointOf(decodeAnalyticsInstance(t, endpoint).NetworkEndpointDetails)
			assert.False(t, got.internetReachable, endpoint)
		}
	})

	t.Run("a rule that admits every address opens a public endpoint", func(t *testing.T) {
		for _, cidr := range []string{"0.0.0.0/0", "0.0.0.0"} {
			inst := decodeAnalyticsInstance(t, `{"networkEndpointType": "PUBLIC", "whitelistedIps": ["203.0.113.0/24", "`+cidr+`"]}`)
			assert.True(t, analyticsEndpointOf(inst.NetworkEndpointDetails).internetReachable, cidr)
		}
	})

	t.Run("no endpoint details is OAC's default, public and open", func(t *testing.T) {
		got := analyticsEndpointOf(decodeAnalyticsInstance(t, "").NetworkEndpointDetails)
		assert.Equal(t, "", got.endpointType)
		assert.True(t, got.internetReachable)
	})
}
