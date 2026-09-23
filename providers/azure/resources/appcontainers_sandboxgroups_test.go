// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	apps "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func sandboxTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

const sandboxGroupID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.App/sandboxGroups/sg1"

func TestSandboxGroupDecode(t *testing.T) {
	t.Run("linked group", func(t *testing.T) {
		var entry apps.SandboxGroup
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "`+sandboxGroupID+`",
			"name": "sg1",
			"type": "Microsoft.App/sandboxGroups",
			"location": "eastus",
			"tags": {"env": "prod"},
			"properties": {
				"provisioningState": "Succeeded",
				"environmentId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env1",
				"defaultDomain": "example.eastus.azurecontainerapps.io"
			}
		}`), &entry))

		g, err := acaSandboxGroupToMQL(sandboxTestRuntime(), &entry)
		require.NoError(t, err)
		assert.Equal(t, sandboxGroupID, g.Id.Data)
		assert.Equal(t, "sg1", g.Name.Data)
		assert.Equal(t, "eastus", g.Location.Data)
		assert.Equal(t, map[string]any{"env": "prod"}, g.Tags.Data)
		assert.Equal(t, "Succeeded", g.ProvisioningState.Data)
		assert.Equal(t, "example.eastus.azurecontainerapps.io", g.DefaultDomain.Data)
		assert.Equal(t, "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env1", g.cacheEnvironmentID)
	})

	t.Run("unlinked group reports null environment and domain", func(t *testing.T) {
		var entry apps.SandboxGroup
		require.NoError(t, json.Unmarshal([]byte(`{"id": "`+sandboxGroupID+`2", "name": "sg2", "location": "eastus", "properties": {"provisioningState": "InProgress"}}`), &entry))

		g, err := acaSandboxGroupToMQL(sandboxTestRuntime(), &entry)
		require.NoError(t, err)
		assert.Equal(t, "InProgress", g.ProvisioningState.Data)
		assert.NotZero(t, g.DefaultDomain.State&plugin.StateIsNull)

		env, err := g.managedEnvironment()
		require.NoError(t, err)
		assert.Nil(t, env)
		assert.NotZero(t, g.ManagedEnvironment.State&plugin.StateIsNull)
	})

	t.Run("no properties block", func(t *testing.T) {
		var entry apps.SandboxGroup
		require.NoError(t, json.Unmarshal([]byte(`{"id": "`+sandboxGroupID+`3", "name": "sg3", "location": "eastus"}`), &entry))

		g, err := acaSandboxGroupToMQL(sandboxTestRuntime(), &entry)
		require.NoError(t, err)
		assert.NotZero(t, g.ProvisioningState.State&plugin.StateIsNull)
	})
}

func TestSandboxVnetConnectionDecode(t *testing.T) {
	var entry apps.VnetConnection
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "`+sandboxGroupID+`/vnetConnections/vc1",
		"name": "vc1",
		"properties": {
			"provisioningState": "Succeeded",
			"subnetId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sandboxes"
		}
	}`), &entry))

	vc, err := acaSandboxVnetConnectionToMQL(sandboxTestRuntime(), &entry)
	require.NoError(t, err)
	assert.Equal(t, "vc1", vc.Name.Data)
	assert.Equal(t, "Succeeded", vc.ProvisioningState.Data)
	assert.Equal(t, "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sandboxes", vc.cacheSubnetID)

	var noSubnet apps.VnetConnection
	require.NoError(t, json.Unmarshal([]byte(`{"id": "`+sandboxGroupID+`/vnetConnections/vc2", "name": "vc2", "properties": {}}`), &noSubnet))
	vc2, err := acaSandboxVnetConnectionToMQL(sandboxTestRuntime(), &noSubnet)
	require.NoError(t, err)
	subnet, err := vc2.subnet()
	require.NoError(t, err)
	assert.Nil(t, subnet)
	assert.NotZero(t, vc2.Subnet.State&plugin.StateIsNull)
	assert.NotZero(t, vc2.ProvisioningState.State&plugin.StateIsNull)
}

// Two sandbox groups in different resource groups can share a name; the cache
// must keep them apart by their full ARM ID.
func TestSandboxGroupsDoNotAlias(t *testing.T) {
	runtime := sandboxTestRuntime()
	mk := func(id, state string) *mqlAzureSubscriptionContainerAppServiceSandboxGroup {
		var entry apps.SandboxGroup
		require.NoError(t, json.Unmarshal([]byte(`{"id": "`+id+`", "name": "sg", "location": "eastus", "properties": {"provisioningState": "`+state+`"}}`), &entry))
		g, err := acaSandboxGroupToMQL(runtime, &entry)
		require.NoError(t, err)
		return g
	}
	a := mk("/subscriptions/s/resourceGroups/rg-a/providers/Microsoft.App/sandboxGroups/sg", "Succeeded")
	b := mk("/subscriptions/s/resourceGroups/rg-b/providers/Microsoft.App/sandboxGroups/sg", "Failed")
	assert.Equal(t, "Succeeded", a.ProvisioningState.Data)
	assert.Equal(t, "Failed", b.ProvisioningState.Data)
}
