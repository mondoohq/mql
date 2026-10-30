// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storagecache/armstoragecache/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The regression this guards: a file system on the platform key omits the whole
// encryption settings tree. Reading it without the guards panics, and reporting
// a placeholder key would say a file system is customer-managed-key protected
// when it is not — the exact reading this resource was added to make.
func TestAmlKeyEncryptionKey(t *testing.T) {
	str := func(s string) *string { return &s }

	t.Run("platform key: no settings at all", func(t *testing.T) {
		keyURL, vaultID := amlKeyEncryptionKey(nil)
		assert.Equal(t, "", keyURL)
		assert.Equal(t, "", vaultID)
	})

	t.Run("settings present but no key", func(t *testing.T) {
		keyURL, vaultID := amlKeyEncryptionKey(&armstoragecache.AmlFilesystemEncryptionSettings{})
		assert.Equal(t, "", keyURL)
		assert.Equal(t, "", vaultID)
	})

	t.Run("key without a source vault", func(t *testing.T) {
		keyURL, vaultID := amlKeyEncryptionKey(&armstoragecache.AmlFilesystemEncryptionSettings{
			KeyEncryptionKey: &armstoragecache.KeyVaultKeyReference{
				KeyURL: str("https://contoso.vault.azure.net/keys/lustre-cmk/abc123"),
			},
		})
		assert.Equal(t, "https://contoso.vault.azure.net/keys/lustre-cmk/abc123", keyURL)
		assert.Equal(t, "", vaultID)
	})

	t.Run("customer-managed key with its vault", func(t *testing.T) {
		keyURL, vaultID := amlKeyEncryptionKey(&armstoragecache.AmlFilesystemEncryptionSettings{
			KeyEncryptionKey: &armstoragecache.KeyVaultKeyReference{
				KeyURL: str("https://contoso.vault.azure.net/keys/lustre-cmk/abc123"),
				SourceVault: &armstoragecache.KeyVaultKeyReferenceSourceVault{
					ID: str("/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/contoso"),
				},
			},
		})
		assert.Equal(t, "https://contoso.vault.azure.net/keys/lustre-cmk/abc123", keyURL)
		assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/contoso", vaultID)
	})

	// The key URL is handed straight to newKeyVaultKeyResource, so it has to be
	// something parseKeyVaultId accepts or the typed reference cannot resolve.
	t.Run("the reported key URL resolves as a key vault identifier", func(t *testing.T) {
		keyURL, _ := amlKeyEncryptionKey(&armstoragecache.AmlFilesystemEncryptionSettings{
			KeyEncryptionKey: &armstoragecache.KeyVaultKeyReference{
				KeyURL: str("https://contoso.vault.azure.net/keys/lustre-cmk/abc123"),
			},
		})
		parsed, err := parseKeyVaultId(keyURL)
		require.NoError(t, err)
		assert.Equal(t, "contoso", parsed.Vault)
		assert.Equal(t, "keys", parsed.Type)
		assert.Equal(t, "lustre-cmk", parsed.Name)
		assert.Equal(t, "abc123", parsed.Version)
	})
}
