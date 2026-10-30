// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/stretchr/testify/assert"
)

func TestStorageTurboTier(t *testing.T) {
	t.Run("absent configuration is null, not disabled", func(t *testing.T) {
		enabled, target := storageTurboTier(nil)
		assert.Nil(t, enabled)
		assert.Nil(t, target)
	})
	t.Run("enabled without target leaves target null", func(t *testing.T) {
		enabled, target := storageTurboTier(&storage.TurboTier{Status: ptr(storage.TurboTierStatusEnabled)})
		if assert.NotNil(t, enabled) {
			assert.True(t, *enabled)
		}
		assert.Nil(t, target)
	})
	t.Run("disabled reads false", func(t *testing.T) {
		enabled, _ := storageTurboTier(&storage.TurboTier{Status: ptr(storage.TurboTierStatusDisabled)})
		if assert.NotNil(t, enabled) {
			assert.False(t, *enabled)
		}
	})
	t.Run("target percent is carried", func(t *testing.T) {
		enabled, target := storageTurboTier(&storage.TurboTier{
			Status:        ptr(storage.TurboTierStatusEnabled),
			TargetPercent: new(int32(35)),
		})
		if assert.NotNil(t, enabled) {
			assert.True(t, *enabled)
		}
		if assert.NotNil(t, target) {
			assert.Equal(t, int64(35), *target)
		}
	})
	t.Run("target without status leaves enabled null", func(t *testing.T) {
		enabled, target := storageTurboTier(&storage.TurboTier{TargetPercent: new(int32(20))})
		assert.Nil(t, enabled)
		if assert.NotNil(t, target) {
			assert.Equal(t, int64(20), *target)
		}
	})
}
