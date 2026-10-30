// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeDataConnectors decodes a data connector list page the way the SDK
// pager does, so each entry arrives as its kind-specific type.
func decodeDataConnectors(t *testing.T, payload string) []armsecurityinsights.DataConnectorClassification {
	t.Helper()
	var list armsecurityinsights.DataConnectorList
	require.NoError(t, json.Unmarshal([]byte(payload), &list))
	return list.Value
}

// Synthetic: the documented shapes of each connector kind (api-version
// 2022-11-01); no subscription available to us had Sentinel onboarded.
const dataConnectorListJSON = `{"value": [
  {"id": "/x/dataConnectors/office", "name": "office", "kind": "Office365",
   "properties": {"tenantId": "2070ecc9-b4d5-4ae4-adaa-936fa1954fa8",
     "dataTypes": {"exchange": {"state": "Enabled"}, "sharePoint": {"state": "Disabled"}, "teams": {"state": "Enabled"}}}},
  {"id": "/x/dataConnectors/mcas", "name": "mcas", "kind": "MicrosoftCloudAppSecurity",
   "properties": {"tenantId": "t-mcas", "dataTypes": {"alerts": {"state": "Enabled"}, "discoveryLogs": {"state": "Disabled"}}}},
  {"id": "/x/dataConnectors/asc", "name": "asc", "kind": "AzureSecurityCenter",
   "properties": {"subscriptionId": "0000", "dataTypes": {"alerts": {"state": "Enabled"}}}},
  {"id": "/x/dataConnectors/aws", "name": "aws", "kind": "AmazonWebServicesCloudTrail",
   "properties": {"awsRoleArn": "arn:aws:iam::123456789012:role/sentinel", "dataTypes": {"logs": {"state": "Enabled"}}}},
  {"id": "/x/dataConnectors/ti", "name": "ti", "kind": "ThreatIntelligence",
   "properties": {"tenantId": "t-ti", "dataTypes": {"indicators": {"state": "Enabled"}}}},
  {"id": "/x/dataConnectors/aad", "name": "aad", "kind": "AzureActiveDirectory",
   "properties": {"tenantId": "t-aad"}},
  {"id": "/x/dataConnectors/new", "name": "new", "kind": "MicrosoftThreatProtection",
   "properties": {"tenantId": "t-new", "dataTypes": {"incidents": {"state": "Enabled"}}}}
]}`

func TestDataConnectorDetails(t *testing.T) {
	connectors := decodeDataConnectors(t, dataConnectorListJSON)
	require.Len(t, connectors, 7)

	byName := map[string]armsecurityinsights.DataConnectorClassification{}
	for _, c := range connectors {
		byName[*c.GetDataConnector().Name] = c
	}

	tests := []struct {
		name       string
		wantTenant any
		wantStates map[string]any
	}{
		{"office", "2070ecc9-b4d5-4ae4-adaa-936fa1954fa8", map[string]any{"exchange": "Enabled", "sharePoint": "Disabled", "teams": "Enabled"}},
		{"mcas", "t-mcas", map[string]any{"alerts": "Enabled", "discoveryLogs": "Disabled"}},
		// AzureSecurityCenter is scoped to a subscription, not a tenant.
		{"asc", nil, map[string]any{"alerts": "Enabled"}},
		{"aws", nil, map[string]any{"logs": "Enabled"}},
		{"ti", "t-ti", map[string]any{"indicators": "Enabled"}},
		// A connector without dataTypes reports no states rather than guessing.
		{"aad", "t-aad", map[string]any{}},
		// A kind the SDK does not model decodes as the bare DataConnector.
		{"new", nil, map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := dataConnectorArgs(byName[tc.name])
			assert.Equal(t, tc.wantTenant, args["tenantId"].Value)
			assert.Equal(t, tc.wantStates, args["dataTypes"].Value)
			assert.Equal(t, "/x/dataConnectors/"+tc.name, args["id"].Value)
		})
	}

	assert.Equal(t, "Office365", dataConnectorArgs(byName["office"])["kind"].Value)
	assert.Equal(t, "MicrosoftThreatProtection", dataConnectorArgs(byName["new"])["kind"].Value)
}
