// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	ml "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mlRegistryBody is a registry list entry with a private endpoint connection
// and two regions, one with Azure-created and one with customer-created
// backing resources.
// Synthetic: shaped after the Microsoft.MachineLearningServices 2024-04-01 REST reference; no target showed this.
func mlRegistryBody(name string) string {
	return `{
  "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.MachineLearningServices/registries/` + name + `",
  "name": "` + name + `",
  "location": "eastus",
  "kind": "Registry",
  "identity": {"type": "SystemAssigned", "principalId": "p-1", "tenantId": "t-1"},
  "properties": {
    "publicNetworkAccess": "Disabled",
    "intellectualPropertyPublisher": "Contoso",
    "discoveryUrl": "https://eastus.api.azureml.ms/registrymanagement/v1.0/registries/` + name + `/discovery",
    "registryPrivateEndpointConnections": [{
      "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.MachineLearningServices/registries/` + name + `/privateEndpointConnections/pe",
      "location": "eastus",
      "properties": {
        "groupIds": ["amlregistry"],
        "privateEndpoint": {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"},
        "provisioningState": "Succeeded",
        "registryPrivateLinkServiceConnectionState": {"status": "Approved", "description": "auto", "actionsRequired": "None"}
      }
    }],
    "regionDetails": [{
      "location": "eastus",
      "acrDetails": [{"systemCreatedAcrAccount": {"acrAccountName": "acr1", "armResourceId": {"resourceId": "/subscriptions/s/resourceGroups/mrg/providers/Microsoft.ContainerRegistry/registries/acr1"}}}],
      "storageAccountDetails": [{"systemCreatedStorageAccount": {"storageAccountName": "sa1", "allowBlobPublicAccess": false, "armResourceId": {"resourceId": "/subscriptions/s/resourceGroups/mrg/providers/Microsoft.Storage/storageAccounts/sa1"}}}]
    }, {
      "location": "westus",
      "acrDetails": [{"userCreatedAcrAccount": {"armResourceId": {"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/byo"}}}],
      "storageAccountDetails": [{"userCreatedStorageAccount": {"armResourceId": {"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/byo"}}}, {}]
    }, {
      "acrDetails": []
    }]
  }
}`
}

func decodeMlRegistry(t *testing.T, body string) *ml.Registry {
	t.Helper()
	var reg ml.Registry
	require.NoError(t, json.Unmarshal([]byte(body), &reg))
	return &reg
}

func TestMachineLearningRegistryToMql(t *testing.T) {
	runtime := cacheIDTestRuntime()
	reg, err := machineLearningRegistryToMql(runtime, decodeMlRegistry(t, mlRegistryBody("models")))
	require.NoError(t, err)

	assert.Equal(t, "Disabled", reg.PublicNetworkAccess.Data)
	assert.Equal(t, "Contoso", reg.IntellectualPropertyPublisher.Data)
	assert.Equal(t, "Registry", reg.Kind.Data)
	assert.True(t, reg.MlFlowRegistryUri.IsNull())
	assert.Equal(t, "p-1", reg.ResourceIdentity.Data.PrincipalId.Data)

	pecs, err := reg.privateEndpointConnections()
	require.NoError(t, err)
	require.Len(t, pecs, 1)
	pec := pecs[0].(*mqlAzureSubscriptionPrivateEndpointConnection)
	assert.Equal(t, "pe", pec.Name.Data)
	// Registries name the connection state registryPrivateLinkServiceConnectionState.
	require.NotNil(t, pec.PrivateLinkServiceConnectionState.Data)
	assert.Equal(t, "Approved", pec.PrivateLinkServiceConnectionState.Data.Status.Data)

	regions, err := reg.regions()
	require.NoError(t, err)
	// The entry without a location is skipped.
	require.Len(t, regions, 2)
	east := regions[0].(*mqlAzureSubscriptionMachineLearningServiceRegistryRegion)
	west := regions[1].(*mqlAzureSubscriptionMachineLearningServiceRegistryRegion)
	assert.Equal(t, "eastus", east.Location.Data)
	assert.Equal(t, []string{"/subscriptions/s/resourceGroups/mrg/providers/Microsoft.ContainerRegistry/registries/acr1"}, east.cacheContainerRegistryIds)
	assert.Equal(t, []string{"/subscriptions/s/resourceGroups/mrg/providers/Microsoft.Storage/storageAccounts/sa1"}, east.cacheStorageAccountIds)
	assert.Equal(t, []string{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/byo"}, west.cacheContainerRegistryIds)
	// The empty storage entry contributes nothing.
	assert.Equal(t, []string{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/byo"}, west.cacheStorageAccountIds)
}

func TestMachineLearningRegistryRegionsAreKeyedByRegistry(t *testing.T) {
	runtime := cacheIDTestRuntime()
	// Synthetic: two registries replicating to the same region; no target showed this.
	a, err := machineLearningRegistryToMql(runtime, decodeMlRegistry(t, mlRegistryBody("reg-a")))
	require.NoError(t, err)
	b, err := machineLearningRegistryToMql(runtime, decodeMlRegistry(t, mlRegistryBody("reg-b")))
	require.NoError(t, err)
	ra, err := a.regions()
	require.NoError(t, err)
	rb, err := b.regions()
	require.NoError(t, err)
	assert.NotSame(t, ra[0], rb[0])
}
