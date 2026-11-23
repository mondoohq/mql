// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	clusters "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestAksDiskCsiDriverEnabled(t *testing.T) {
	t.Run("nil storage profile returns nil", func(t *testing.T) {
		assert.Nil(t, aksDiskCsiDriverEnabled(nil))
	})
	t.Run("nil disk driver returns nil", func(t *testing.T) {
		assert.Nil(t, aksDiskCsiDriverEnabled(&clusters.ManagedClusterStorageProfile{}))
	})
	t.Run("enabled true", func(t *testing.T) {
		enabled := true
		sp := &clusters.ManagedClusterStorageProfile{
			DiskCSIDriver: &clusters.ManagedClusterStorageProfileDiskCSIDriver{Enabled: &enabled},
		}
		got := aksDiskCsiDriverEnabled(sp)
		assert.NotNil(t, got)
		assert.True(t, *got)
	})
}

func TestAksKubernetesResourceObjectEncryption(t *testing.T) {
	t.Run("nil security profile returns nil", func(t *testing.T) {
		assert.Nil(t, aksKubernetesResourceObjectEncryption(nil))
	})
	t.Run("security profile without the encryption profile returns nil", func(t *testing.T) {
		assert.Nil(t, aksKubernetesResourceObjectEncryption(&clusters.ManagedClusterSecurityProfile{}))
	})
	t.Run("encryption profile without a value returns nil", func(t *testing.T) {
		sp := &clusters.ManagedClusterSecurityProfile{
			KubernetesResourceObjectEncryptionProfile: &clusters.KubernetesResourceObjectEncryptionProfile{},
		}
		assert.Nil(t, aksKubernetesResourceObjectEncryption(sp))
	})
	t.Run("enabled from ARM response", func(t *testing.T) {
		raw := `{"kubernetesResourceObjectEncryptionProfile":{"infrastructureEncryption":"Enabled"}}`
		var sp clusters.ManagedClusterSecurityProfile
		require.NoError(t, json.Unmarshal([]byte(raw), &sp))
		got := aksKubernetesResourceObjectEncryption(&sp)
		require.NotNil(t, got)
		assert.Equal(t, "Enabled", *got)
	})
}

func TestAksSku(t *testing.T) {
	t.Run("nil sku", func(t *testing.T) {
		name, tier := aksSku(nil)
		assert.Empty(t, name)
		assert.Empty(t, tier)
	})
	t.Run("standard cluster from ARM response", func(t *testing.T) {
		var sku clusters.ManagedClusterSKU
		require.NoError(t, json.Unmarshal([]byte(`{"name":"Base","tier":"Free"}`), &sku))
		name, tier := aksSku(&sku)
		assert.Equal(t, "Base", name)
		assert.Equal(t, "Free", tier)
	})
	t.Run("AKS Automatic cluster from ARM response", func(t *testing.T) {
		var mc clusters.ManagedCluster
		require.NoError(t, json.Unmarshal([]byte(`{"name":"automatic","sku":{"name":"Automatic","tier":"Standard"},"properties":{}}`), &mc))
		name, tier := aksSku(mc.SKU)
		assert.Equal(t, "Automatic", name)
		assert.Equal(t, "Standard", tier)
	})
	t.Run("tier without a name", func(t *testing.T) {
		tierValue := clusters.ManagedClusterSKUTierPremium
		name, tier := aksSku(&clusters.ManagedClusterSKU{Tier: &tierValue})
		assert.Empty(t, name)
		assert.Equal(t, "Premium", tier)
	})
}

// A discovered AKS cluster asset carries the id from the ARM resource listing
// (".../resourceGroups/..."), while the AKS API that lists the clusters spells
// it ".../resourcegroups/...". The cluster must still resolve on its own asset.
func TestInitAksClusterMatchesIDCaseInsensitively(t *testing.T) {
	const assetID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c-1"
	const listedID = "/subscriptions/sub-1/resourcegroups/rg/providers/Microsoft.ContainerService/managedClusters/c-1"

	runtime := runtimeForAsset(t, []string{assetID})
	svcRes, err := NewResource(runtime, ResourceAzureSubscriptionAksService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData("sub-1"),
	})
	require.NoError(t, err)
	cluster, err := CreateResource(runtime, ResourceAzureSubscriptionAksServiceCluster, map[string]*llx.RawData{
		"id": llx.StringData(listedID),
	})
	require.NoError(t, err)
	svc := svcRes.(*mqlAzureSubscriptionAksService)
	svc.Clusters = plugin.TValue[[]any]{Data: []any{cluster}, State: plugin.StateIsSet}

	_, res, err := initAzureSubscriptionAksServiceCluster(runtime, map[string]*llx.RawData{})
	require.NoError(t, err)
	assert.Same(t, cluster, res)
}

func TestAksContainerInsightsEnabled(t *testing.T) {
	// Synthetic: the two places Container insights can be switched on, plus
	// the disabled and absent cases; no target showed these.
	assert.False(t, aksContainerInsightsEnabled(nil))
	assert.False(t, aksContainerInsightsEnabled(&clusters.ManagedClusterProperties{}))
	assert.True(t, aksContainerInsightsEnabled(&clusters.ManagedClusterProperties{
		AzureMonitorProfile: &clusters.ManagedClusterAzureMonitorProfile{
			ContainerInsights: &clusters.ManagedClusterAzureMonitorProfileContainerInsights{Enabled: ptr(true)},
		},
	}))
	assert.True(t, aksContainerInsightsEnabled(&clusters.ManagedClusterProperties{
		AddonProfiles: map[string]*clusters.ManagedClusterAddonProfile{"omsAgent": {Enabled: ptr(true)}},
	}))
	assert.False(t, aksContainerInsightsEnabled(&clusters.ManagedClusterProperties{
		AddonProfiles: map[string]*clusters.ManagedClusterAddonProfile{
			"omsagent":                  {Enabled: ptr(false)},
			"azurepolicy":               {Enabled: ptr(true)},
			"ingressApplicationGateway": nil,
		},
		AzureMonitorProfile: &clusters.ManagedClusterAzureMonitorProfile{
			ContainerInsights: &clusters.ManagedClusterAzureMonitorProfileContainerInsights{Enabled: ptr(false)},
		},
	}))
}

func TestAksCustomPrivateDNSZoneID(t *testing.T) {
	// Synthetic: the documented setting values; no target showed these.
	zone := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/privatelink.eastus.azmk8s.io"
	assert.Equal(t, zone, aksCustomPrivateDNSZoneID(zone))
	assert.Empty(t, aksCustomPrivateDNSZoneID("system"))
	assert.Empty(t, aksCustomPrivateDNSZoneID("System"))
	assert.Empty(t, aksCustomPrivateDNSZoneID("none"))
	assert.Empty(t, aksCustomPrivateDNSZoneID(""))
}
