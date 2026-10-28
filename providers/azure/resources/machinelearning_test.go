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
