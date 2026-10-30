// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create pointers using generics
//
//go:fix inline
func ptr[T any](v T) *T {
	return new(v)
}

func TestAzureSubscriptionCacheServiceRedis(t *testing.T) {
	// Create mock data
	mockRedisCache := &armredis.ResourceInfo{
		ID:       new("/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.Cache/redis/test-cache"),
		Name:     new("test-cache"),
		Type:     new("Microsoft.Cache/redis"),
		Location: new("eastus"),
		Zones:    []*string{new("1"), new("2")},
		Identity: &armredis.ManagedServiceIdentity{
			Type:        ptr(armredis.ManagedServiceIdentityTypeSystemAssigned),
			PrincipalID: new("principal-123"),
			TenantID:    new("tenant-456"),
		},
		Properties: &armredis.Properties{
			HostName:            new("test-cache.redis.cache.windows.net"),
			EnableNonSSLPort:    new(true),
			PublicNetworkAccess: ptr(armredis.PublicNetworkAccessEnabled),
			Port:                new(int32(6379)),
			SSLPort:             new(int32(6380)),
			ProvisioningState:   ptr(armredis.ProvisioningStateSucceeded),
			RedisVersion:        new("6.0"),
			ReplicasPerMaster:   new(int32(1)),
			ReplicasPerPrimary:  new(int32(1)),
			MinimumTLSVersion:   ptr(armredis.TLSVersionOne2),
			ShardCount:          new(int32(3)),
			StaticIP:            new("10.0.0.5"),
			SubnetID:            new("/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/test-subnet"),
			RedisConfiguration: &armredis.CommonPropertiesRedisConfiguration{
				MaxmemoryPolicy:  new("allkeys-lru"),
				RdbBackupEnabled: new("true"),
			},
			SKU: &armredis.SKU{
				Name:     ptr(armredis.SKUNameStandard),
				Capacity: new(int32(1)),
				Family:   ptr(armredis.SKUFamilyC),
			},
		},
		Tags: map[string]*string{
			"Environment": new("Test"),
			"Project":     new("Redis-Test"),
		},
	}

	t.Run("TestRedisDataConversion", func(t *testing.T) {
		// runtime is nil because mock data has no PrivateEndpointConnections;
		// if PECs are added, a real runtime is needed to avoid nil dereference in CreateResource.
		rawData, err := createRedisInstanceRawData(azureTestRuntime(), mockRedisCache)
		require.NoError(t, err)
		require.NotNil(t, rawData)

		// Verify basic fields
		assert.Equal(t, "/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.Cache/redis/test-cache", rawData["id"].Value)
		assert.Equal(t, "test-cache", rawData["name"].Value)
		assert.Equal(t, "Microsoft.Cache/redis", rawData["type"].Value)
		assert.Equal(t, "eastus", rawData["location"].Value)
		assert.Equal(t, "test-cache.redis.cache.windows.net", rawData["hostName"].Value)
		assert.Equal(t, true, rawData["enableNonSslPort"].Value)
		assert.Equal(t, int64(6379), rawData["port"].Value)
		assert.Equal(t, int64(6380), rawData["sslPort"].Value)
		assert.Equal(t, "6.0", rawData["redisVersion"].Value)
		assert.Equal(t, int64(1), rawData["replicasPerMaster"].Value)
		assert.Equal(t, int64(1), rawData["replicasPerPrimary"].Value)

		// Verify enum conversions via the actual conversion function output
		assert.Equal(t, "Enabled", rawData["publicNetworkAccess"].Value)
		assert.Equal(t, "Succeeded", rawData["provisioningState"].Value)
		assert.Equal(t, "1.2", rawData["minimumTlsVersion"].Value)

		// Verify properties dict contains expected data (this is the full cache object serialized)
		properties, ok := rawData["properties"].Value.(map[string]any)
		require.True(t, ok, "properties should be a map[string]any")
		assert.Equal(t, "test-cache", properties["name"])
		assert.Equal(t, "eastus", properties["location"])

		// Verify SKU dict contains expected data
		sku, ok := rawData["sku"].Value.(map[string]any)
		require.True(t, ok, "sku should be a map[string]any")
		assert.Equal(t, "Standard", sku["name"])
		assert.Equal(t, "C", sku["family"])

		// Verify tags contain expected keys and values
		tags, ok := rawData["tags"].Value.(map[string]any)
		require.True(t, ok, "tags should be a map[string]any")
		assert.Equal(t, "Test", tags["Environment"])
		assert.Equal(t, "Redis-Test", tags["Project"])

		// Verify new fields
		assert.Equal(t, int64(3), rawData["shardCount"].Value)
		assert.Equal(t, "10.0.0.5", rawData["staticIp"].Value)
		assert.Equal(t, "/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/test-subnet", rawData["subnetId"].Value)

		// Verify zones
		require.Contains(t, rawData, "zones")
		zones, ok := rawData["zones"].Value.([]any)
		require.True(t, ok, "zones should be a []any")
		assert.Len(t, zones, 2)
		assert.Equal(t, "1", zones[0])
		assert.Equal(t, "2", zones[1])

		// Verify redisConfiguration dict contains expected data
		redisConfig, ok := rawData["redisConfiguration"].Value.(map[string]any)
		require.True(t, ok, "redisConfiguration should be a map[string]any")
		assert.Equal(t, "allkeys-lru", redisConfig["maxmemory-policy"])
		assert.Equal(t, "true", redisConfig["rdb-backup-enabled"])

		// Verify identity dict contains expected data
		identity, ok := rawData["identity"].Value.(map[string]any)
		require.True(t, ok, "identity should be a map[string]any")
		assert.Equal(t, "principal-123", identity["principalId"])
		assert.Equal(t, "tenant-456", identity["tenantId"])

		// privateEndpointConnections is now lazy-loaded and no longer in rawData
	})

	t.Run("TestNilOptionalFields", func(t *testing.T) {
		// Test with minimal mock data to ensure nil fields are handled gracefully.
		minimalCache := &armredis.ResourceInfo{
			ID:       new("/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.Cache/redis/minimal-cache"),
			Name:     new("minimal-cache"),
			Type:     new("Microsoft.Cache/redis"),
			Location: new("westus"),
			Properties: &armredis.Properties{
				SKU: &armredis.SKU{
					Name:     ptr(armredis.SKUNameBasic),
					Capacity: new(int32(0)),
					Family:   ptr(armredis.SKUFamilyC),
				},
			},
		}

		rawData, err := createRedisInstanceRawData(azureTestRuntime(), minimalCache)
		require.NoError(t, err)
		require.NotNil(t, rawData)

		// Nil enum fields should result in nil string values
		assert.Nil(t, rawData["minimumTlsVersion"].Value)
		assert.Nil(t, rawData["publicNetworkAccess"].Value)
		assert.Nil(t, rawData["provisioningState"].Value)

		// Nil optional fields
		assert.Nil(t, rawData["staticIp"].Value)
		assert.Nil(t, rawData["subnetId"].Value)
		assert.Nil(t, rawData["shardCount"].Value)
		assert.Nil(t, rawData["hostName"].Value)
		assert.Nil(t, rawData["enableNonSslPort"].Value)
		assert.Nil(t, rawData["port"].Value)
		assert.Nil(t, rawData["sslPort"].Value)
		assert.Nil(t, rawData["redisVersion"].Value)
		assert.Nil(t, rawData["replicasPerMaster"].Value)
		assert.Nil(t, rawData["replicasPerPrimary"].Value)

		// Empty zones
		require.Contains(t, rawData, "zones")
		zones, ok := rawData["zones"].Value.([]any)
		require.True(t, ok, "zones should be a []any")
		assert.Len(t, zones, 0)

		// Nil identity
		assert.Nil(t, rawData["identity"].Value)

		// Nil redisConfiguration
		assert.Nil(t, rawData["redisConfiguration"].Value)

		// privateEndpointConnections is now lazy-loaded and no longer in rawData
	})
}
