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

// decodeCompute decodes an ARM compute resource body through the SDK, so the
// test exercises the same polymorphic unmarshal the provider sees.
func decodeCompute(t *testing.T, body string) ml.ComputeClassification {
	t.Helper()
	var res ml.ComputeResource
	require.NoError(t, json.Unmarshal([]byte(body), &res))
	return res.Properties
}

func TestMlComputeNodeAccessFrom(t *testing.T) {
	t.Run("compute instance", func(t *testing.T) {
		// Synthetic: field names follow the ARM compute REST schema; no target showed this.
		c := decodeCompute(t, `{"properties":{"computeType":"ComputeInstance","properties":{
			"enableNodePublicIp":false,
			"sshSettings":{"sshPublicAccess":"Enabled"},
			"subnet":{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vn/subnets/ml"},
			"personalComputeInstanceSettings":{"assignedUser":{"objectId":"11111111-1111-1111-1111-111111111111","tenantId":"22222222-2222-2222-2222-222222222222"}}
		}}}`)
		got := mlComputeNodeAccessFrom(c)
		require.NotNil(t, got.enableNodePublicIP)
		assert.False(t, *got.enableNodePublicIP)
		require.NotNil(t, got.sshPublicAccess)
		assert.Equal(t, "Enabled", *got.sshPublicAccess)
		require.NotNil(t, got.subnetID)
		assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vn/subnets/ml", *got.subnetID)
		require.NotNil(t, got.assignedUserObjectID)
		assert.Equal(t, "11111111-1111-1111-1111-111111111111", *got.assignedUserObjectID)
		require.NotNil(t, got.assignedUserTenantID)
		assert.Equal(t, "22222222-2222-2222-2222-222222222222", *got.assignedUserTenantID)
	})

	t.Run("compute instance without optional settings", func(t *testing.T) {
		// Synthetic: a shared instance outside any subnet; no target showed this.
		c := decodeCompute(t, `{"properties":{"computeType":"ComputeInstance","properties":{"vmSize":"STANDARD_DS3_V2"}}}`)
		got := mlComputeNodeAccessFrom(c)
		assert.Nil(t, got.enableNodePublicIP)
		assert.Nil(t, got.sshPublicAccess)
		assert.Nil(t, got.subnetID)
		assert.Nil(t, got.assignedUserObjectID)
		assert.Nil(t, got.assignedUserTenantID)
	})

	t.Run("aml compute cluster", func(t *testing.T) {
		// Synthetic: field names follow the ARM compute REST schema; no target showed this.
		c := decodeCompute(t, `{"properties":{"computeType":"AmlCompute","properties":{
			"enableNodePublicIp":true,
			"remoteLoginPortPublicAccess":"NotSpecified",
			"subnet":{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vn/subnets/train"}
		}}}`)
		got := mlComputeNodeAccessFrom(c)
		require.NotNil(t, got.enableNodePublicIP)
		assert.True(t, *got.enableNodePublicIP)
		require.NotNil(t, got.sshPublicAccess)
		assert.Equal(t, "NotSpecified", *got.sshPublicAccess)
		require.NotNil(t, got.subnetID)
		assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vn/subnets/train", *got.subnetID)
		// Clusters have no assigned user.
		assert.Nil(t, got.assignedUserObjectID)
		assert.Nil(t, got.assignedUserTenantID)
	})

	t.Run("other compute type", func(t *testing.T) {
		// Synthetic: attached Kubernetes compute has none of these settings; no target showed this.
		c := decodeCompute(t, `{"properties":{"computeType":"Kubernetes","properties":{"namespace":"default"}}}`)
		got := mlComputeNodeAccessFrom(c)
		assert.Equal(t, mlComputeNodeAccess{}, got)
	})

	t.Run("nil properties", func(t *testing.T) {
		// Synthetic: list entry without properties; no target showed this.
		assert.Equal(t, mlComputeNodeAccess{}, mlComputeNodeAccessFrom(nil))
	})
}

// mlWorkspaceBody is a workspace list entry with a managed network and a
// shared private link.
// Synthetic: shaped after the Microsoft.MachineLearningServices 2024-04-01 REST reference; no target showed this.
func mlWorkspaceBody(name, linkStatus string) string {
	return `{
  "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/` + name + `",
  "name": "` + name + `",
  "properties": {
    "managedNetwork": {
      "isolationMode": "AllowOnlyApprovedOutbound",
      "status": {"status": "Active", "sparkReady": false}
    },
    "privateEndpointConnections": [{
      "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/` + name + `/privateEndpointConnections/pe",
      "name": "pe",
      "properties": {
        "privateEndpoint": {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe-` + name + `"},
        "privateLinkServiceConnectionState": {"status": "Approved"}
      }
    }],
    "sharedPrivateLinkResources": [{
      "name": "to-storage",
      "properties": {
        "groupId": "blob",
        "privateLinkResourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data",
        "status": "` + linkStatus + `"
      }
    }]
  }
}`
}

func TestMachineLearningWorkspaceNetworkIsolation(t *testing.T) {
	runtime := cacheIDTestRuntime()
	decode := func(body string) *mqlAzureSubscriptionMachineLearningServiceWorkspace {
		var ws ml.Workspace
		require.NoError(t, json.Unmarshal([]byte(body), &ws))
		mqlWs, err := machineLearningWorkspaceToMql(runtime, &ws)
		require.NoError(t, err)
		return mqlWs
	}
	a := decode(mlWorkspaceBody("ws-a", "Approved"))
	b := decode(mlWorkspaceBody("ws-b", "Pending"))

	assert.Equal(t, "Active", a.ManagedNetworkStatus.Data)
	assert.False(t, a.ManagedNetworkSparkReady.Data)
	assert.False(t, a.ManagedNetworkSparkReady.IsNull())

	pecs, err := a.privateLinkConnections()
	require.NoError(t, err)
	require.Len(t, pecs, 1)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe-ws-a",
		pecs[0].(*mqlAzureSubscriptionPrivateEndpointConnection).cachePrivateEndpointId)

	// Two workspaces with a same-named link must not share a cache entry.
	linksA, err := a.sharedPrivateLinks()
	require.NoError(t, err)
	linksB, err := b.sharedPrivateLinks()
	require.NoError(t, err)
	require.Len(t, linksA, 1)
	require.Len(t, linksB, 1)
	la := linksA[0].(*mqlAzureSubscriptionMachineLearningServiceWorkspaceSharedPrivateLink)
	lb := linksB[0].(*mqlAzureSubscriptionMachineLearningServiceWorkspaceSharedPrivateLink)
	assert.Equal(t, "Approved", la.Status.Data)
	assert.Equal(t, "Pending", lb.Status.Data)
	assert.Equal(t, "blob", lb.GroupId.Data)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data", lb.PrivateLinkResourceId.Data)
}

func TestMachineLearningWorkspaceWithoutManagedNetwork(t *testing.T) {
	// Synthetic: a workspace with no managed network; no target showed this.
	var ws ml.Workspace
	require.NoError(t, json.Unmarshal([]byte(`{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/plain","properties":{}}`), &ws))
	mqlWs, err := machineLearningWorkspaceToMql(cacheIDTestRuntime(), &ws)
	require.NoError(t, err)
	assert.True(t, mqlWs.ManagedNetworkStatus.IsNull())
	assert.True(t, mqlWs.ManagedNetworkSparkReady.IsNull())
	links, err := mqlWs.sharedPrivateLinks()
	require.NoError(t, err)
	assert.Empty(t, links)
}

func TestMlSystemDatastoresAuthMode(t *testing.T) {
	// Measured: two workspaces read at API version 2025-09-01, 2026-11-27.
	// One set to identity-based access, one to key access; Azure returned
	// both lowercased.
	assert.Equal(t, "identity", mlSystemDatastoresAuthMode(new("identity")))
	assert.Equal(t, "accesskey", mlSystemDatastoresAuthMode(new("accesskey")))
	// Synthetic: the API enum spells the values in PascalCase.
	assert.Equal(t, "identity", mlSystemDatastoresAuthMode(new("Identity")))
	assert.Equal(t, "userdelegationsas", mlSystemDatastoresAuthMode(new("UserDelegationSAS")))
	// Synthetic: a workspace that never set the mode uses the account key.
	assert.Equal(t, "accesskey", mlSystemDatastoresAuthMode(nil))
	assert.Equal(t, "accesskey", mlSystemDatastoresAuthMode(new("")))
}

func TestMlComputeInstanceSettings(t *testing.T) {
	// Synthetic: shaped as the 2025-09-01 ComputeInstanceProperties model.
	body := `{"properties":{"computeType":"ComputeInstance","properties":{
		"idleTimeBeforeShutdown":"PT30M",
		"schedules":{"computeStartStop":[
			{"id":"s1","action":"Stop","status":"Enabled","triggerType":"Cron","provisioningStatus":"Completed",
			 "cron":{"expression":"0 18 * * 1-5","timeZone":"UTC"},"schedule":{"status":"Enabled"}},
			null
		]}}}}`
	var resp mlComputeInstanceResponse
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	s := resp.settings()
	assert.Equal(t, "PT30M", s.idleTimeBeforeShutdown)
	require.Len(t, s.schedules, 1)
	sched := s.schedules[0].(map[string]any)
	assert.Equal(t, "Stop", sched["action"])
	assert.Equal(t, "Cron", sched["triggerType"])
	assert.Equal(t, "0 18 * * 1-5", sched["cron"].(map[string]any)["expression"])
	assert.NotContains(t, sched, "schedule", "the deprecated schedule block is dropped")

	// Synthetic: an instance with neither setting has idle shutdown off and no
	// schedule, an empty list rather than null.
	var bare mlComputeInstanceResponse
	require.NoError(t, json.Unmarshal([]byte(`{"properties":{"computeType":"ComputeInstance","properties":{}}}`), &bare))
	s = bare.settings()
	assert.Equal(t, "", s.idleTimeBeforeShutdown)
	assert.NotNil(t, s.schedules)
	assert.Empty(t, s.schedules)

	assert.Equal(t, "", mlComputeInstanceResponse{}.settings().idleTimeBeforeShutdown)
}

func TestIso8601DurationMinutes(t *testing.T) {
	// Synthetic: Azure accepts 15 minutes to 3 days.
	for in, want := range map[string]int64{
		"PT15M":     15,
		"PT30M":     30,
		"PT1H":      60,
		"PT1H30M":   90,
		"PT90S":     1,
		"PT59S":     0,
		"P1D":       1440,
		"P3D":       4320,
		"P1DT2H":    1560,
		"P1W":       10080,
		"PT0.5H":    30,
		"pt45m":     45,
		"PT1H0M30S": 60,
	} {
		got, err := iso8601DurationMinutes(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "P", "PT", "30M", "P1M", "P1Y", "PT1D", "P1H", "PTM", "P1DT", "PT1H2"} {
		_, err := iso8601DurationMinutes(in)
		assert.Error(t, err, in)
	}
}
