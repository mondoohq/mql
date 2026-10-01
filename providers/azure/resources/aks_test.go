// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	clusters "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
