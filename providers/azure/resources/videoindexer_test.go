// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVideoIndexerAccountDecode(t *testing.T) {
	// Synthetic: shaped as the 2025-04-01 Accounts_Get example; no account was
	// available to measure.
	body := `{
		"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.VideoIndexer/accounts/vi",
		"name":"vi","location":"eastus","tags":{"a":"b"},
		"identity":{"type":"UserAssigned","userAssignedIdentities":{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi":{}}},
		"properties":{
			"tenantId":"t","accountId":"3575690b-a569-449c-ab7b-11020f948f76","accountName":"vi",
			"storageServices":{"resourceId":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
				"userAssignedIdentity":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi"},
			"openAiServices":{"resourceId":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/oai"},
			"totalSecondsIndexed":600,"totalMinutesIndexed":10,
			"publicNetworkAccess":"Disabled",
			"privateEndpointConnections":[{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.VideoIndexer/accounts/vi/privateEndpointConnections/pe",
				"properties":{"privateEndpoint":{"id":"/pe"},"privateLinkServiceConnectionState":{"status":"Approved"}}}],
			"provisioningState":"Succeeded"}}`
	var acc videoIndexerAccount
	require.NoError(t, json.Unmarshal([]byte(body), &acc))
	require.NotNil(t, acc.Properties)
	p := acc.Properties
	assert.Equal(t, "vi", *acc.Name)
	assert.Equal(t, "3575690b-a569-449c-ab7b-11020f948f76", *p.AccountID)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa", *p.StorageServices.ResourceID)
	assert.True(t, isUserAssignedIdentityID(*p.StorageServices.UserAssignedIdentity))
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/oai", *p.OpenAiServices.ResourceID)
	assert.Nil(t, p.OpenAiServices.UserAssignedIdentity)
	assert.Equal(t, int64(10), *p.TotalMinutesIndexed)
	assert.Equal(t, "Disabled", orDefault(p.PublicNetworkAccess, "Enabled"))
	require.Len(t, p.PrivateEndpointConnections, 1)
	assert.Equal(t, "Succeeded", *p.ProvisioningState)

	// Synthetic: an account created before publicNetworkAccess existed omits
	// it, and is reachable from the public internet.
	var old videoIndexerAccount
	require.NoError(t, json.Unmarshal([]byte(`{"id":"x","properties":{"accountId":"y"}}`), &old))
	assert.Equal(t, "Enabled", orDefault(old.Properties.PublicNetworkAccess, "Enabled"))
	assert.Nil(t, old.Properties.StorageServices)
}
