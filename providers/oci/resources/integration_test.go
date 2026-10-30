// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeIntegrationInstance decodes one item of a ListIntegrationInstances
// response, so the polymorphic networkEndpointDetails goes through the SDK's
// own unmarshalling, as it does on a live call.
func decodeIntegrationInstance(t *testing.T, body string) integration.IntegrationInstanceSummary {
	t.Helper()
	var inst integration.IntegrationInstanceSummary
	require.NoError(t, json.Unmarshal([]byte(body), &inst))
	return inst
}

func TestIntegrationNetworkAccess(t *testing.T) {
	const base = `"id": "ocid1.integrationinstance.oc1..x", "displayName": "oic", "compartmentId": "ocid1.compartment.oc1..c",
		"integrationInstanceType": "STANDARD", "isByol": false, "instanceUrl": "https://oic.example", "messagePacks": 1`

	t.Run("no restriction is reachable from anywhere", func(t *testing.T) {
		inst := decodeIntegrationInstance(t, `{`+base+`}`)
		got, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
		require.NoError(t, err)
		assert.Equal(t, "", got.endpointType)
		assert.Nil(t, got.details, "an unrestricted instance has no endpoint details")
		assert.Empty(t, got.allowlistedIps)
		assert.Empty(t, got.allowlistedVcns)
		assert.True(t, got.internetReachable)
	})

	t.Run("an allowlist restricts access", func(t *testing.T) {
		inst := decodeIntegrationInstance(t, `{`+base+`, "networkEndpointDetails": {
			"networkEndpointType": "PUBLIC",
			"allowlistedHttpIps": ["203.0.113.0/24"],
			"allowlistedHttpVcns": [{"id": "ocid1.vcn.oc1..v", "allowlistedIps": ["10.0.0.0/16"]}, {"id": "ocid1.vcn.oc1..w"}],
			"isIntegrationVcnAllowlisted": true
		}}`)
		got, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
		require.NoError(t, err)
		assert.Equal(t, "PUBLIC", got.endpointType)
		assert.Equal(t, []any{"203.0.113.0/24"}, got.allowlistedIps)
		assert.Equal(t, []any{
			map[string]any{"id": "ocid1.vcn.oc1..v", "allowlistedIps": []any{"10.0.0.0/16"}},
			map[string]any{"id": "ocid1.vcn.oc1..w", "allowlistedIps": []any{}},
		}, got.allowlistedVcns)
		assert.True(t, got.integrationVcnAllowlisted)
		assert.Equal(t, "PUBLIC", got.details["networkEndpointType"])
		assert.False(t, got.internetReachable)
	})

	t.Run("an empty restriction admits nobody", func(t *testing.T) {
		inst := decodeIntegrationInstance(t, `{`+base+`, "networkEndpointDetails": {"networkEndpointType": "PUBLIC"}}`)
		got, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
		require.NoError(t, err)
		assert.Equal(t, "PUBLIC", got.endpointType)
		assert.False(t, got.internetReachable)
	})

	t.Run("an allowlist that admits every address is no restriction", func(t *testing.T) {
		inst := decodeIntegrationInstance(t, `{`+base+`, "networkEndpointDetails": {
			"networkEndpointType": "PUBLIC", "allowlistedHttpIps": ["203.0.113.0/24", "0.0.0.0/0"]}}`)
		got, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
		require.NoError(t, err)
		assert.True(t, got.internetReachable)
	})

	t.Run("a runtime or design-time allowlist can open the instance", func(t *testing.T) {
		for _, component := range []string{"runtime", "designTime"} {
			inst := decodeIntegrationInstance(t, `{`+base+`, "networkEndpointDetails": {
				"networkEndpointType": "PUBLIC", "allowlistedHttpIps": ["203.0.113.0/24"],
				"`+component+`": {"allowlistedHttpIps": ["0.0.0.0/0"]}}}`)
			got, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
			require.NoError(t, err)
			assert.True(t, got.internetReachable, component)
			assert.Contains(t, got.details, component)
		}
	})

	t.Run("a restricted runtime allowlist stays restricted", func(t *testing.T) {
		inst := decodeIntegrationInstance(t, `{`+base+`, "networkEndpointDetails": {
			"networkEndpointType": "PUBLIC", "runtime": {"allowlistedHttpIps": ["198.51.100.7"]}}}`)
		got, err := integrationNetworkAccessOf(inst.NetworkEndpointDetails)
		require.NoError(t, err)
		assert.False(t, got.internetReachable)
	})
}
