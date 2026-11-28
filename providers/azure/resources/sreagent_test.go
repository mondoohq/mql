// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSreAgentDecode(t *testing.T) {
	// Synthetic: the 2026-01-01 Agents_Get example; no agent was available to
	// measure.
	body := `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/agents/a","name":"a","location":"East US",
		"identity":{"type":"SystemAssigned","principalId":"p","tenantId":"t"},
		"properties":{"provisioningState":"Succeeded","agentEndpoint":"https://a.eastus.agents.azurecontainerapps.io",
			"runningState":"Running","powerState":"Running","upgradeChannel":"Stable",
			"knowledgeGraphConfiguration":{"identity":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/kg",
				"managedResources":["/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/teststorage","/subscriptions/s/resourceGroups/app-rg"]},
			"actionConfiguration":{"identity":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/act","mode":"Autonomous","accessLevel":"High"}}}`
	var agent sreAgent
	require.NoError(t, json.Unmarshal([]byte(body), &agent))
	p := agent.Properties
	require.NotNil(t, p)
	assert.Equal(t, "Autonomous", *p.ActionConfiguration.Mode)
	assert.Equal(t, "High", *p.ActionConfiguration.AccessLevel)
	assert.True(t, isUserAssignedIdentityID(*p.ActionConfiguration.Identity))
	assert.True(t, isUserAssignedIdentityID(*p.KnowledgeGraphConfiguration.Identity))
	assert.Len(t, p.KnowledgeGraphConfiguration.ManagedResources, 2)
	assert.Equal(t, "Running", *p.PowerState)
	assert.Equal(t, "Stable", *p.UpgradeChannel)
}

func TestResourceGroupScopes(t *testing.T) {
	// Synthetic cases.
	got := resourceGroupScopes([]any{
		"/subscriptions/s/resourceGroups/App-RG",
		"/subscriptions/s/resourcegroups/other/",
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
		"/subscriptions/s",
		"",
		42,
	})
	assert.Equal(t, map[string]struct{}{
		"/subscriptions/s/resourcegroups/app-rg": {},
		"/subscriptions/s/resourcegroups/other":  {},
	}, got)
	assert.Empty(t, resourceGroupScopes(nil))
}
