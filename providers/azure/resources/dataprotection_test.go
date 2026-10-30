// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The regression this guards: a vault reports one storage setting per
// datastore, and folding them into a map is what lets a check ask for the vault
// store's redundancy directly. A setting missing either half must be dropped
// rather than recorded under an empty key, which would read as a datastore
// called "" with a redundancy of "".
func TestBackupVaultStorageRedundancy(t *testing.T) {
	store := func(s armdataprotection.StorageSettingStoreTypes) *armdataprotection.StorageSettingStoreTypes {
		return &s
	}
	redundancy := func(s armdataprotection.StorageSettingTypes) *armdataprotection.StorageSettingTypes {
		return &s
	}

	t.Run("no settings is an empty map, never nil", func(t *testing.T) {
		res := backupVaultStorageRedundancy(nil)
		require.NotNil(t, res)
		assert.Empty(t, res)
	})

	t.Run("nil entries are skipped", func(t *testing.T) {
		res := backupVaultStorageRedundancy([]*armdataprotection.StorageSetting{nil, nil})
		assert.Empty(t, res)
	})

	t.Run("each datastore keys its own redundancy", func(t *testing.T) {
		res := backupVaultStorageRedundancy([]*armdataprotection.StorageSetting{
			{
				DatastoreType: store(armdataprotection.StorageSettingStoreTypesVaultStore),
				Type:          redundancy(armdataprotection.StorageSettingTypesGeoRedundant),
			},
			{
				DatastoreType: store(armdataprotection.StorageSettingStoreTypesOperationalStore),
				Type:          redundancy(armdataprotection.StorageSettingTypesLocallyRedundant),
			},
		})
		assert.Equal(t, map[string]any{
			"VaultStore":       "GeoRedundant",
			"OperationalStore": "LocallyRedundant",
		}, res)
	})

	t.Run("a setting missing either half is dropped, not keyed on empty", func(t *testing.T) {
		res := backupVaultStorageRedundancy([]*armdataprotection.StorageSetting{
			{Type: redundancy(armdataprotection.StorageSettingTypesZoneRedundant)},
			{DatastoreType: store(armdataprotection.StorageSettingStoreTypesArchiveStore)},
			{},
		})
		assert.Empty(t, res)
		assert.NotContains(t, res, "")
	})
}
