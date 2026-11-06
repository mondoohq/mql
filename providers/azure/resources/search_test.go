// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchServiceInternetReachable(t *testing.T) {
	tests := []struct {
		name      string
		pna       string
		ipRules   []string
		want      bool
		wantKnown bool
	}{
		// Synthetic: public access disabled ignores even a catch-all rule; no target showed this.
		{"disabled", "disabled", []string{"0.0.0.0/0"}, false, true},
		// Synthetic: enabled with no IP rules has no firewall; no target showed this.
		{"enabled without rules", "enabled", nil, true, true},
		// Synthetic: enabled with narrow rules is an allowlist; no target showed this.
		{"enabled with narrow rules", "enabled", []string{"203.0.113.0/24", "198.51.100.7"}, false, true},
		// Synthetic: enabled with a catch-all rule; no target showed this.
		{"enabled with catch-all rule", "enabled", []string{"0.0.0.0/0"}, true, true},
		// Synthetic: two halves of IPv4 together cover the internet; no target showed this.
		{"enabled with split halves", "enabled", []string{"0.0.0.0/1", "128.0.0.0/1"}, true, true},
		// Synthetic: a network security perimeter decides, so the answer is unknown; no target showed this.
		{"secured by perimeter", "securedByPerimeter", nil, false, false},
		// Synthetic: services predating the property report it empty and are public; no target showed this.
		{"empty public access", "", nil, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := searchServiceInternetReachable(tt.pna, tt.ipRules)
			assert.Equal(t, tt.wantKnown, known)
			assert.Equal(t, tt.want, got)
		})
	}
}

// searchServiceWithLinks is a search service list entry carrying a private
// endpoint connection and two shared private links.
// Synthetic: shaped after the Microsoft.Search 2025-05-01 REST reference; no target showed this.
const searchServiceWithLinks = `{
  "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Search/searchServices/srch",
  "name": "srch",
  "location": "eastus",
  "properties": {
    "publicNetworkAccess": "disabled",
    "privateEndpointConnections": [{
      "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Search/searchServices/srch/privateEndpointConnections/pe1",
      "name": "pe1",
      "properties": {
        "privateEndpoint": {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe1"},
        "privateLinkServiceConnectionState": {"status": "Approved", "description": "ok", "actionsRequired": "None"},
        "provisioningState": "Succeeded"
      }
    }],
    "sharedPrivateLinkResources": [{
      "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Search/searchServices/srch/sharedPrivateLinkResources/blob",
      "name": "blob",
      "properties": {
        "groupId": "blob",
        "privateLinkResourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/docs",
        "requestMessage": "indexer access",
        "status": "Approved",
        "provisioningState": "Succeeded"
      }
    }, {
      "name": "no-id",
      "properties": {"groupId": "sqlServer"}
    }, {
      "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Search/searchServices/srch/sharedPrivateLinkResources/aks",
      "name": "aks",
      "properties": {
        "groupId": "management",
        "privateLinkResourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/k",
        "resourceRegion": "westus2",
        "status": "Pending"
      }
    }]
  }
}`

func TestSearchServicePrivateLinks(t *testing.T) {
	var svc armsearch.Service
	require.NoError(t, json.Unmarshal([]byte(searchServiceWithLinks), &svc))
	mqlSvc, err := searchServiceToMql(cacheIDTestRuntime(), &svc)
	require.NoError(t, err)

	pecs, err := mqlSvc.privateEndpointConnections()
	require.NoError(t, err)
	require.Len(t, pecs, 1)
	pec := pecs[0].(*mqlAzureSubscriptionPrivateEndpointConnection)
	assert.Equal(t, "pe1", pec.Name.Data)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe1", pec.cachePrivateEndpointId)

	links, err := mqlSvc.sharedPrivateLinks()
	require.NoError(t, err)
	// The id-less entry is skipped.
	require.Len(t, links, 2)
	blob := links[0].(*mqlAzureSubscriptionSearchServiceServiceSharedPrivateLink)
	assert.Equal(t, "blob", blob.GroupId.Data)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/docs", blob.PrivateLinkResourceId.Data)
	assert.Equal(t, "Approved", blob.Status.Data)
	assert.Equal(t, "Succeeded", blob.ProvisioningState.Data)
	assert.Equal(t, "indexer access", blob.RequestMessage.Data)
	assert.True(t, blob.ResourceRegion.IsNull())

	aks := links[1].(*mqlAzureSubscriptionSearchServiceServiceSharedPrivateLink)
	assert.Equal(t, "westus2", aks.ResourceRegion.Data)
	assert.Equal(t, "Pending", aks.Status.Data)
	assert.True(t, aks.ProvisioningState.IsNull())
}
