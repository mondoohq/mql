// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

// telemetryItems builds a name->RegistryKeyItem map (lower-cased keys, as the
// loader produces) from name/value pairs for use in the pure-function tests.
func telemetryItems(pairs map[string]int64) map[string]registry.RegistryKeyItem {
	items := map[string]registry.RegistryKeyItem{}
	for name, num := range pairs {
		lower := name
		// emulate the loader's lower-casing without importing strings here
		for i := 0; i < len(lower); i++ {
			if c := lower[i]; c >= 'A' && c <= 'Z' {
				b := []byte(lower)
				b[i] = c + 32
				lower = string(b)
			}
		}
		items[lower] = registry.RegistryKeyItem{
			Key:   name,
			Value: registry.RegistryKeyValue{Number: num},
		}
	}
	return items
}

func TestComputeTelemetry(t *testing.T) {
	t.Run("all absent yields all nil", func(t *testing.T) {
		v := computeTelemetry(map[string]registry.RegistryKeyItem{})
		assert.Nil(t, v.allowTelemetry)
		assert.Nil(t, v.disableEnterpriseAuthProxy)
		assert.Nil(t, v.disableOneSettingsDownloads)
		assert.Nil(t, v.doNotShowFeedbackNotifications)
		assert.Nil(t, v.enableOneSettingsAuditing)
		assert.Nil(t, v.limitDiagnosticLogCollection)
		assert.Nil(t, v.limitDumpCollection)
	})

	t.Run("nil map yields all nil", func(t *testing.T) {
		v := computeTelemetry(nil)
		assert.Nil(t, v.allowTelemetry)
		assert.Nil(t, v.limitDumpCollection)
	})

	t.Run("explicit zeros are preserved as non-nil", func(t *testing.T) {
		// the hardened/CIS posture for AllowTelemetry is 0 (Security); it must
		// remain distinguishable from "not configured"
		v := computeTelemetry(telemetryItems(map[string]int64{
			"AllowTelemetry":                 0,
			"DisableEnterpriseAuthProxy":     0,
			"DisableOneSettingsDownloads":    0,
			"DoNotShowFeedbackNotifications": 0,
			"EnableOneSettingsAuditing":      0,
			"LimitDiagnosticLogCollection":   0,
			"LimitDumpCollection":            0,
		}))
		require.NotNil(t, v.allowTelemetry)
		assert.Equal(t, int64(0), *v.allowTelemetry)
		require.NotNil(t, v.disableEnterpriseAuthProxy)
		assert.Equal(t, false, *v.disableEnterpriseAuthProxy)
		require.NotNil(t, v.disableOneSettingsDownloads)
		assert.Equal(t, false, *v.disableOneSettingsDownloads)
		require.NotNil(t, v.doNotShowFeedbackNotifications)
		assert.Equal(t, false, *v.doNotShowFeedbackNotifications)
		require.NotNil(t, v.enableOneSettingsAuditing)
		assert.Equal(t, false, *v.enableOneSettingsAuditing)
		require.NotNil(t, v.limitDiagnosticLogCollection)
		assert.Equal(t, false, *v.limitDiagnosticLogCollection)
		require.NotNil(t, v.limitDumpCollection)
		assert.Equal(t, false, *v.limitDumpCollection)
	})

	t.Run("typical hardened values map through", func(t *testing.T) {
		v := computeTelemetry(telemetryItems(map[string]int64{
			"AllowTelemetry":                 1, // Basic/Required
			"DisableEnterpriseAuthProxy":     1,
			"DisableOneSettingsDownloads":    1,
			"DoNotShowFeedbackNotifications": 1,
			"EnableOneSettingsAuditing":      1,
			"LimitDiagnosticLogCollection":   1,
			"LimitDumpCollection":            1,
		}))
		require.NotNil(t, v.allowTelemetry)
		assert.Equal(t, int64(1), *v.allowTelemetry)
		require.NotNil(t, v.enableOneSettingsAuditing)
		assert.Equal(t, true, *v.enableOneSettingsAuditing)
	})

	t.Run("partial configuration leaves unset fields nil", func(t *testing.T) {
		v := computeTelemetry(telemetryItems(map[string]int64{
			"AllowTelemetry": 2, // Enhanced
		}))
		require.NotNil(t, v.allowTelemetry)
		assert.Equal(t, int64(2), *v.allowTelemetry)
		assert.Nil(t, v.disableEnterpriseAuthProxy)
		assert.Nil(t, v.limitDumpCollection)
	})

	t.Run("AllowTelemetry full level (3) maps through", func(t *testing.T) {
		v := computeTelemetry(telemetryItems(map[string]int64{"AllowTelemetry": 3}))
		require.NotNil(t, v.allowTelemetry)
		assert.Equal(t, int64(3), *v.allowTelemetry)
	})
}

func TestComputeConsumerContent(t *testing.T) {
	t.Run("all absent yields all nil", func(t *testing.T) {
		v := computeConsumerContent(map[string]registry.RegistryKeyItem{})
		assert.Nil(t, v.disableCloudOptimizedContent)
		assert.Nil(t, v.disableConsumerAccountStateContent)
		assert.Nil(t, v.disableWindowsConsumerFeatures)
	})

	t.Run("nil map yields all nil", func(t *testing.T) {
		v := computeConsumerContent(nil)
		assert.Nil(t, v.disableWindowsConsumerFeatures)
	})

	t.Run("explicit zeros preserved as non-nil", func(t *testing.T) {
		v := computeConsumerContent(telemetryItems(map[string]int64{
			"DisableCloudOptimizedContent":       0,
			"DisableConsumerAccountStateContent": 0,
			"DisableWindowsConsumerFeatures":     0,
		}))
		require.NotNil(t, v.disableCloudOptimizedContent)
		assert.Equal(t, false, *v.disableCloudOptimizedContent)
		require.NotNil(t, v.disableConsumerAccountStateContent)
		assert.Equal(t, false, *v.disableConsumerAccountStateContent)
		require.NotNil(t, v.disableWindowsConsumerFeatures)
		assert.Equal(t, false, *v.disableWindowsConsumerFeatures)
	})

	t.Run("hardened values (all 1) map through", func(t *testing.T) {
		v := computeConsumerContent(telemetryItems(map[string]int64{
			"DisableCloudOptimizedContent":       1,
			"DisableConsumerAccountStateContent": 1,
			"DisableWindowsConsumerFeatures":     1,
		}))
		require.NotNil(t, v.disableCloudOptimizedContent)
		assert.Equal(t, true, *v.disableCloudOptimizedContent)
		require.NotNil(t, v.disableConsumerAccountStateContent)
		assert.Equal(t, true, *v.disableConsumerAccountStateContent)
		require.NotNil(t, v.disableWindowsConsumerFeatures)
		assert.Equal(t, true, *v.disableWindowsConsumerFeatures)
	})

	t.Run("partial configuration leaves unset fields nil", func(t *testing.T) {
		v := computeConsumerContent(telemetryItems(map[string]int64{
			"DisableWindowsConsumerFeatures": 1,
		}))
		require.NotNil(t, v.disableWindowsConsumerFeatures)
		assert.Equal(t, true, *v.disableWindowsConsumerFeatures)
		assert.Nil(t, v.disableCloudOptimizedContent)
		assert.Nil(t, v.disableConsumerAccountStateContent)
	})
}
