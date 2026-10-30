// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	armbatch "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch/v4"
	"github.com/stretchr/testify/assert"
)

func TestBatchAccountDataConversion(t *testing.T) {
	aadMode := armbatch.AuthenticationModeAAD
	sharedKeyMode := armbatch.AuthenticationModeSharedKey

	mockAccount := &armbatch.Account{
		ID:       new("/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/test-account"),
		Name:     new("test-account"),
		Type:     new("Microsoft.Batch/batchAccounts"),
		Location: new("eastus"),
		Identity: &armbatch.AccountIdentity{
			Type:        ptr(armbatch.ResourceIdentityTypeSystemAssigned),
			PrincipalID: new("principal-123"),
			TenantID:    new("tenant-456"),
		},
		Properties: &armbatch.AccountProperties{
			AccountEndpoint:                       new("test-account.eastus.batch.azure.com"),
			ProvisioningState:                     ptr(armbatch.ProvisioningStateSucceeded),
			PoolAllocationMode:                    ptr(armbatch.PoolAllocationModeBatchService),
			PublicNetworkAccess:                   ptr(armbatch.PublicNetworkAccessTypeEnabled),
			NodeManagementEndpoint:                new("https://test-account.eastus.service.batch.azure.com"),
			ActiveJobAndJobScheduleQuota:          new(int32(300)),
			DedicatedCoreQuota:                    new(int32(500)),
			DedicatedCoreQuotaPerVMFamilyEnforced: new(true),
			LowPriorityCoreQuota:                  new(int32(100)),
			PoolQuota:                             new(int32(64)),
			AllowedAuthenticationModes: []*armbatch.AuthenticationMode{
				&aadMode,
				&sharedKeyMode,
			},
		},
		Tags: map[string]*string{
			"Environment": new("Test"),
			"Team":        new("Platform"),
		},
	}

	t.Run("FullDataConversion", func(t *testing.T) {
		rawData, err := createBatchAccountRawData(mockAccount)
		assert.NoError(t, err)
		assert.NotNil(t, rawData)

		assert.Equal(t, "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/test-account", rawData["id"].Value)
		assert.Equal(t, "test-account", rawData["name"].Value)
		assert.Equal(t, "Microsoft.Batch/batchAccounts", rawData["type"].Value)
		assert.Equal(t, "eastus", rawData["location"].Value)

		// String fields
		assert.Equal(t, "test-account.eastus.batch.azure.com", rawData["accountEndpoint"].Value)
		assert.Equal(t, "https://test-account.eastus.service.batch.azure.com", rawData["nodeManagementEndpoint"].Value)

		// Enum fields converted to strings
		assert.Equal(t, "Succeeded", rawData["provisioningState"].Value)
		assert.Equal(t, "BatchService", rawData["poolAllocationMode"].Value)
		assert.Equal(t, "Enabled", rawData["publicNetworkAccess"].Value)

		// Quota fields
		assert.Equal(t, int64(300), rawData["activeJobAndJobScheduleQuota"].Value)
		assert.Equal(t, int64(500), rawData["dedicatedCoreQuota"].Value)
		assert.Equal(t, int64(100), rawData["lowPriorityCoreQuota"].Value)
		assert.Equal(t, int64(64), rawData["poolQuota"].Value)
		assert.Equal(t, true, rawData["dedicatedCoreQuotaPerVmFamilyEnforced"].Value)

		// Array of enums
		authModes := rawData["allowedAuthenticationModes"].Value.([]any)
		assert.Len(t, authModes, 2)
		assert.Equal(t, "AAD", authModes[0])
		assert.Equal(t, "SharedKey", authModes[1])

		// Dict fields
		assert.NotNil(t, rawData["properties"].Value)
		assert.NotNil(t, rawData["tags"].Value)
		assert.Equal(t, "principal-123", rawData["principalId"].Value)
	})

	t.Run("EnumConversions", func(t *testing.T) {
		provisioningState := string(*mockAccount.Properties.ProvisioningState)
		assert.Equal(t, "Succeeded", provisioningState)

		poolAllocationMode := string(*mockAccount.Properties.PoolAllocationMode)
		assert.Equal(t, "BatchService", poolAllocationMode)

		publicNetworkAccess := string(*mockAccount.Properties.PublicNetworkAccess)
		assert.Equal(t, "Enabled", publicNetworkAccess)
	})

	t.Run("NilOptionalFields", func(t *testing.T) {
		minimalAccount := &armbatch.Account{
			ID:       new("/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/minimal"),
			Name:     new("minimal"),
			Type:     new("Microsoft.Batch/batchAccounts"),
			Location: new("westus"),
			Properties: &armbatch.AccountProperties{
				ProvisioningState: ptr(armbatch.ProvisioningStateSucceeded),
			},
		}

		rawData, err := createBatchAccountRawData(minimalAccount)
		assert.NoError(t, err)
		assert.NotNil(t, rawData)

		// Nil optional fields
		assert.Nil(t, rawData["accountEndpoint"].Value)
		assert.Nil(t, rawData["poolAllocationMode"].Value)
		assert.Nil(t, rawData["publicNetworkAccess"].Value)
		assert.Nil(t, rawData["nodeManagementEndpoint"].Value)
		assert.Nil(t, rawData["activeJobAndJobScheduleQuota"].Value)
		assert.Nil(t, rawData["dedicatedCoreQuota"].Value)
		assert.Nil(t, rawData["lowPriorityCoreQuota"].Value)
		assert.Nil(t, rawData["poolQuota"].Value)
		assert.Nil(t, rawData["dedicatedCoreQuotaPerVmFamilyEnforced"].Value)
		assert.Nil(t, rawData["allowedAuthenticationModes"].Value)
		assert.Nil(t, rawData["networkProfile"].Value)
		assert.Nil(t, rawData["privateEndpointConnections"].Value)
		assert.Nil(t, rawData["dedicatedCoreQuotaPerVmFamily"].Value)

		// Nil identity
		assert.Equal(t, "", rawData["principalId"].Value)

		// Present fields still work
		assert.Equal(t, "Succeeded", rawData["provisioningState"].Value)
	})

	t.Run("NilProperties", func(t *testing.T) {
		noPropsAccount := &armbatch.Account{
			ID:       new("/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/no-props"),
			Name:     new("no-props"),
			Type:     new("Microsoft.Batch/batchAccounts"),
			Location: new("westus"),
		}

		rawData, err := createBatchAccountRawData(noPropsAccount)
		assert.NoError(t, err)
		assert.NotNil(t, rawData)

		assert.Equal(t, "no-props", rawData["name"].Value)
		assert.Nil(t, rawData["properties"].Value)
		assert.Nil(t, rawData["provisioningState"].Value)
	})
}

func TestBatchPoolDataConversion(t *testing.T) {
	mockPool := &armbatch.Pool{
		ID:   new("/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/test-account/pools/test-pool"),
		Name: new("test-pool"),
		Type: new("Microsoft.Batch/batchAccounts/pools"),
		Etag: new("W/\"0x8D12345678\""),
		Properties: &armbatch.PoolProperties{
			VMSize:            new("Standard_D2s_v3"),
			ProvisioningState: ptr(armbatch.PoolProvisioningStateSucceeded),
			DeploymentConfiguration: &armbatch.DeploymentConfiguration{
				VirtualMachineConfiguration: &armbatch.VirtualMachineConfiguration{
					NodeAgentSKUID: new("batch.node.ubuntu 22.04"),
					ImageReference: &armbatch.ImageReference{
						Publisher: new("canonical"),
						Offer:     new("0001-com-ubuntu-server-jammy"),
						SKU:       new("22_04-lts"),
						Version:   new("latest"),
					},
				},
			},
		},
	}

	t.Run("FullDataConversion", func(t *testing.T) {
		rawData, err := createBatchPoolRawData(azureTestRuntime(), mockPool)
		assert.NoError(t, err)
		assert.NotNil(t, rawData)

		assert.Equal(t, "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/test-account/pools/test-pool", rawData["id"].Value)
		assert.Equal(t, "test-pool", rawData["name"].Value)
		assert.Equal(t, "Microsoft.Batch/batchAccounts/pools", rawData["type"].Value)
		assert.Equal(t, "W/\"0x8D12345678\"", rawData["etag"].Value)
		assert.Equal(t, "Standard_D2s_v3", rawData["vmSize"].Value)
		assert.Equal(t, "Succeeded", rawData["provisioningState"].Value)

		// Dict fields
		assert.NotNil(t, rawData["properties"].Value)
		assert.NotNil(t, rawData["deploymentConfiguration"].Value)
		assert.NotNil(t, rawData["virtualMachineConfiguration"].Value)
	})

	t.Run("NilOptionalFields", func(t *testing.T) {
		minimalPool := &armbatch.Pool{
			ID:   new("/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Batch/batchAccounts/test-account/pools/minimal"),
			Name: new("minimal"),
			Type: new("Microsoft.Batch/batchAccounts/pools"),
		}

		rawData, err := createBatchPoolRawData(azureTestRuntime(), minimalPool)
		assert.NoError(t, err)
		assert.NotNil(t, rawData)

		assert.Equal(t, "minimal", rawData["name"].Value)
		assert.Nil(t, rawData["etag"].Value)
		assert.Nil(t, rawData["properties"].Value)
		assert.Nil(t, rawData["identity"].Value)
		assert.Nil(t, rawData["deploymentConfiguration"].Value)
		assert.Nil(t, rawData["virtualMachineConfiguration"].Value)
		assert.Nil(t, rawData["vmSize"].Value)
		assert.Nil(t, rawData["provisioningState"].Value)
	})
}
