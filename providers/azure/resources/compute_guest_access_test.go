// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVmGuestAccessSettings(t *testing.T) {
	t.Run("nil properties leave every flag null", func(t *testing.T) {
		access := vmGuestAccessSettings(nil)
		assert.Nil(t, access.allowExtensionOperations)
		assert.Nil(t, access.requireGuestProvisionSignal)
		assert.Nil(t, access.winRmHTTPListenerEnabled)
		assert.Nil(t, access.winRmHTTPSListenerEnabled)
		assert.Nil(t, access.certificateSourceVaultIDs)
		assert.Empty(t, access.encryptionIdentityID)
	})

	t.Run("an absent os profile leaves the guest flags null", func(t *testing.T) {
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{})
		assert.Nil(t, access.allowExtensionOperations)
		assert.Nil(t, access.requireGuestProvisionSignal)
	})

	t.Run("extension operations disabled", func(t *testing.T) {
		no := false
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{
			OSProfile: &compute.OSProfile{AllowExtensionOperations: &no},
		})
		require.NotNil(t, access.allowExtensionOperations)
		assert.False(t, *access.allowExtensionOperations)
	})

	t.Run("a linux vm has no winrm verdict at all", func(t *testing.T) {
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{
			OSProfile: &compute.OSProfile{LinuxConfiguration: &compute.LinuxConfiguration{}},
		})
		assert.Nil(t, access.winRmHTTPListenerEnabled)
		assert.Nil(t, access.winRmHTTPSListenerEnabled)
	})

	t.Run("a windows vm with no winrm block reports both listeners off", func(t *testing.T) {
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{
			OSProfile: &compute.OSProfile{WindowsConfiguration: &compute.WindowsConfiguration{}},
		})
		require.NotNil(t, access.winRmHTTPListenerEnabled)
		require.NotNil(t, access.winRmHTTPSListenerEnabled)
		assert.False(t, *access.winRmHTTPListenerEnabled)
		assert.False(t, *access.winRmHTTPSListenerEnabled)
	})

	t.Run("an http winrm listener is reported on its own", func(t *testing.T) {
		http := compute.ProtocolTypesHTTP
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{
			OSProfile: &compute.OSProfile{
				WindowsConfiguration: &compute.WindowsConfiguration{
					WinRM: &compute.WinRMConfiguration{
						Listeners: []*compute.WinRMListener{nil, {Protocol: &http}},
					},
				},
			},
		})
		require.NotNil(t, access.winRmHTTPListenerEnabled)
		assert.True(t, *access.winRmHTTPListenerEnabled)
		assert.False(t, *access.winRmHTTPSListenerEnabled)
	})

	t.Run("both listeners", func(t *testing.T) {
		httpProto := compute.ProtocolTypesHTTP
		httpsProto := compute.ProtocolTypesHTTPS
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{
			OSProfile: &compute.OSProfile{
				WindowsConfiguration: &compute.WindowsConfiguration{
					WinRM: &compute.WinRMConfiguration{
						Listeners: []*compute.WinRMListener{{Protocol: &httpsProto}, {Protocol: &httpProto}},
					},
				},
			},
		})
		assert.True(t, *access.winRmHTTPListenerEnabled)
		assert.True(t, *access.winRmHTTPSListenerEnabled)
	})

	t.Run("certificate source vaults and the encryption identity", func(t *testing.T) {
		vault := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
		blank := ""
		identity := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ade"
		access := vmGuestAccessSettings(&compute.VirtualMachineProperties{
			OSProfile: &compute.OSProfile{
				Secrets: []*compute.VaultSecretGroup{
					nil,
					{},
					{SourceVault: &compute.SubResource{ID: &blank}},
					{SourceVault: &compute.SubResource{ID: &vault}},
				},
			},
			SecurityProfile: &compute.SecurityProfile{
				EncryptionIdentity: &compute.EncryptionIdentity{UserAssignedIdentityResourceID: &identity},
			},
		})
		assert.Equal(t, []string{vault}, access.certificateSourceVaultIDs)
		assert.Equal(t, identity, access.encryptionIdentityID)
	})
}
