// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	monitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateLinkScopeArgs(t *testing.T) {
	t.Run("scope with access mode settings", func(t *testing.T) {
		// Synthetic: the documented shape of an AMPLS (api-version
		// 2021-07-01-preview); no subscription available to us had one.
		payload := `{
		  "id": "/subscriptions/0000/resourceGroups/rg/providers/microsoft.insights/privateLinkScopes/ampls",
		  "name": "ampls",
		  "location": "Global",
		  "tags": {"env": "prod"},
		  "properties": {
		    "provisioningState": "Succeeded",
		    "accessModeSettings": {
		      "ingestionAccessMode": "PrivateOnly",
		      "queryAccessMode": "Open",
		      "exclusions": [
		        {"privateEndpointConnectionName": "pe-conn", "ingestionAccessMode": "Open", "queryAccessMode": "PrivateOnly"}
		      ]
		    }
		  }
		}`
		var scope monitor.AzureMonitorPrivateLinkScope
		require.NoError(t, json.Unmarshal([]byte(payload), &scope))

		args := privateLinkScopeArgs(&scope)
		assert.Equal(t, "PrivateOnly", args["ingestionAccessMode"].Value)
		assert.Equal(t, "Open", args["queryAccessMode"].Value)
		assert.Equal(t, "Succeeded", args["provisioningState"].Value)
		assert.Equal(t, map[string]any{"env": "prod"}, args["tags"].Value)
		assert.Equal(t, []any{map[string]any{
			"privateEndpointConnectionName": "pe-conn",
			"ingestionAccessMode":           "Open",
			"queryAccessMode":               "PrivateOnly",
		}}, args["accessModeExclusions"].Value)
	})

	t.Run("no access mode settings reads as null", func(t *testing.T) {
		// Synthetic: a scope without accessModeSettings; no target showed this.
		args := privateLinkScopeArgs(&monitor.AzureMonitorPrivateLinkScope{
			ID:         new("/s"),
			Properties: &monitor.AzureMonitorPrivateLinkScopeProperties{},
		})
		assert.Nil(t, args["ingestionAccessMode"].Value)
		assert.Nil(t, args["queryAccessMode"].Value)
		assert.Empty(t, args["accessModeExclusions"].Value)
	})
}

func TestMonitorLinkedResourceKind(t *testing.T) {
	// Synthetic: the ID shapes ARM uses for each linked kind; no target showed these.
	assert.Equal(t, monitorLinkedWorkspace,
		monitorLinkedResourceKind("/subscriptions/0000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"))
	assert.Equal(t, monitorLinkedWorkspace,
		monitorLinkedResourceKind("/subscriptions/0000/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/ws"))
	assert.Equal(t, monitorLinkedApplicationInsight,
		monitorLinkedResourceKind("/subscriptions/0000/resourceGroups/rg/providers/microsoft.insights/components/app"))
	assert.Equal(t, "",
		monitorLinkedResourceKind("/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce"))
	assert.Equal(t, "", monitorLinkedResourceKind(""))
}

func TestPrivateLinkScopeIDsFromScopedResources(t *testing.T) {
	// Synthetic: workspace privateLinkScopedResources entries; no target showed these.
	scope := "/subscriptions/0000/resourceGroups/rg/providers/microsoft.insights/privateLinkScopes/ampls"
	other := "/subscriptions/0000/resourceGroups/rg/providers/microsoft.insights/privateLinkScopes/other"
	entries := []*armoperationalinsights.PrivateLinkScopedResource{
		{ResourceID: new(scope + "/scopedResources/ws-link")},
		nil,
		{ResourceID: nil, ScopeID: new("e2c5d1b6")},
		// The same scope again, cased differently: ARM ids are case-insensitive.
		{ResourceID: new("/subscriptions/0000/resourceGroups/rg/providers/microsoft.insights/privatelinkscopes/AMPLS/scopedresources/ws-link-2")},
		// An entry that names the scope itself rather than a scoped resource.
		{ResourceID: new(other)},
	}
	assert.Equal(t, []string{scope, other}, privateLinkScopeIDsFromScopedResources(entries))
	assert.Empty(t, privateLinkScopeIDsFromScopedResources(nil))
}

func TestScopedResourceArgs(t *testing.T) {
	// Synthetic: the documented shape of a scoped resource; no target showed this.
	payload := `{
	  "id": "/subscriptions/0000/resourceGroups/rg/providers/microsoft.insights/privateLinkScopes/ampls/scopedResources/ws-link",
	  "name": "ws-link",
	  "properties": {
	    "kind": "Resource",
	    "linkedResourceId": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws",
	    "provisioningState": "Succeeded"
	  }
	}`
	var sr monitor.ScopedResource
	require.NoError(t, json.Unmarshal([]byte(payload), &sr))
	args := scopedResourceArgs(&sr)
	assert.Equal(t, "Resource", args["kind"].Value)
	assert.Equal(t, "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws", args["linkedResourceId"].Value)
	assert.Nil(t, args["subscriptionLocation"].Value)
}
