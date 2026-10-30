// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

// dwordItems builds a name->item map mirroring what readDeviceGuardKey produces:
// lower-cased value names mapping to registry items carrying a numeric value.
func dwordItems(values map[string]int64) map[string]registry.RegistryKeyItem {
	items := make(map[string]registry.RegistryKeyItem, len(values))
	for name, v := range values {
		items[name] = registry.RegistryKeyItem{
			Key:   name,
			Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: v},
		}
	}
	return items
}

func TestRegIntPtr(t *testing.T) {
	t.Run("present returns a pointer to the value", func(t *testing.T) {
		items := dwordItems(map[string]int64{"enablevirtualizationbasedsecurity": 1})
		got := regIntPtr(items, "EnableVirtualizationBasedSecurity")
		require.NotNil(t, got)
		assert.Equal(t, int64(1), *got)
	})

	t.Run("explicit 0 is distinguishable from absent", func(t *testing.T) {
		items := dwordItems(map[string]int64{"enablevirtualizationbasedsecurity": 0})
		got := regIntPtr(items, "EnableVirtualizationBasedSecurity")
		require.NotNil(t, got)
		assert.Equal(t, int64(0), *got)
	})

	t.Run("absent returns nil", func(t *testing.T) {
		assert.Nil(t, regIntPtr(dwordItems(map[string]int64{}), "EnableVirtualizationBasedSecurity"))
		assert.Nil(t, regIntPtr(nil, "EnableVirtualizationBasedSecurity"))
	})

	t.Run("value name matching is case insensitive", func(t *testing.T) {
		items := dwordItems(map[string]int64{"lsacfgflags": 2})
		got := regIntPtr(items, "LsaCfgFlags")
		require.NotNil(t, got)
		assert.Equal(t, int64(2), *got)
	})
}

func TestComputeDeviceGuard(t *testing.T) {
	t.Run("empty registry yields all-null fields", func(t *testing.T) {
		v := computeDeviceGuard(dwordItems(map[string]int64{}))
		assert.Nil(t, v.virtualizationBasedSecurityEnabled)
		assert.Nil(t, v.requirePlatformSecurityFeatures)
		assert.Nil(t, v.hypervisorEnforcedCodeIntegrity)
		assert.Nil(t, v.hvciMatRequired)
		assert.Nil(t, v.credentialGuardConfig)
		assert.Nil(t, v.systemGuardLaunch)
		assert.Nil(t, v.kernelShadowStacksLaunch)
	})

	t.Run("nil map yields all-null fields", func(t *testing.T) {
		v := computeDeviceGuard(nil)
		assert.Nil(t, v.virtualizationBasedSecurityEnabled)
		assert.Nil(t, v.kernelShadowStacksLaunch)
	})

	t.Run("fully hardened CIS values map to the right fields", func(t *testing.T) {
		// A CIS-compliant Device Guard configuration: VBS on with Secure Boot +
		// DMA, HVCI enabled with lock, MAT required, Credential Guard with UEFI
		// lock, System Guard and kernel shadow stacks enabled.
		v := computeDeviceGuard(dwordItems(map[string]int64{
			"enablevirtualizationbasedsecurity": 1,
			"requireplatformsecurityfeatures":   3,
			"hypervisorenforcedcodeintegrity":   1,
			"hvcimatrequired":                   1,
			"lsacfgflags":                       1,
			"configuresystemguardlaunch":        1,
			"configurekernelshadowstackslaunch": 1,
		}))
		require.NotNil(t, v.virtualizationBasedSecurityEnabled)
		assert.Equal(t, true, *v.virtualizationBasedSecurityEnabled)
		require.NotNil(t, v.requirePlatformSecurityFeatures)
		assert.Equal(t, int64(3), *v.requirePlatformSecurityFeatures)
		require.NotNil(t, v.hypervisorEnforcedCodeIntegrity)
		assert.Equal(t, int64(1), *v.hypervisorEnforcedCodeIntegrity)
		require.NotNil(t, v.hvciMatRequired)
		assert.Equal(t, true, *v.hvciMatRequired)
		require.NotNil(t, v.credentialGuardConfig)
		assert.Equal(t, int64(1), *v.credentialGuardConfig)
		require.NotNil(t, v.systemGuardLaunch)
		assert.Equal(t, true, *v.systemGuardLaunch)
		require.NotNil(t, v.kernelShadowStacksLaunch)
		assert.Equal(t, int64(1), *v.kernelShadowStacksLaunch)
	})

	t.Run("each value maps to its own field (no cross-wiring)", func(t *testing.T) {
		// Distinct values per name guard against accidental copy/paste mapping.
		v := computeDeviceGuard(dwordItems(map[string]int64{
			"enablevirtualizationbasedsecurity": 1,
			"requireplatformsecurityfeatures":   3,
			"hypervisorenforcedcodeintegrity":   2,
			"hvcimatrequired":                   0,
			"lsacfgflags":                       2,
			"configuresystemguardlaunch":        0,
			"configurekernelshadowstackslaunch": 2,
		}))
		assert.Equal(t, true, *v.virtualizationBasedSecurityEnabled)
		assert.Equal(t, int64(3), *v.requirePlatformSecurityFeatures)
		assert.Equal(t, int64(2), *v.hypervisorEnforcedCodeIntegrity)
		assert.Equal(t, false, *v.hvciMatRequired)
		assert.Equal(t, int64(2), *v.credentialGuardConfig)
		// 0 leaves Secure Launch unmanaged, which is not a policy decision
		assert.Nil(t, v.systemGuardLaunch)
		assert.Equal(t, int64(2), *v.kernelShadowStacksLaunch)
	})

	t.Run("systemGuardLaunch decodes the Secure Launch enumeration", func(t *testing.T) {
		for _, tc := range []struct {
			value int64
			want  *bool
		}{
			{1, new(true)},
			{2, new(false)}, // disabled by policy, read as enabled before
			{0, nil},        // unmanaged
			{3, nil},        // not defined by the policy
		} {
			v := computeDeviceGuard(dwordItems(map[string]int64{"configuresystemguardlaunch": tc.value}))
			assert.Equal(t, tc.want, v.systemGuardLaunch, "ConfigureSystemGuardLaunch=%d", tc.value)
		}
	})

	t.Run("explicit 0 stays distinguishable from null in the struct", func(t *testing.T) {
		// VBS explicitly disabled (0) must be non-nil; Credential Guard absent
		// must be nil.
		v := computeDeviceGuard(dwordItems(map[string]int64{
			"enablevirtualizationbasedsecurity": 0,
		}))
		require.NotNil(t, v.virtualizationBasedSecurityEnabled)
		assert.Equal(t, false, *v.virtualizationBasedSecurityEnabled)
		assert.Nil(t, v.credentialGuardConfig)
	})

	t.Run("partial configuration leaves unset values null", func(t *testing.T) {
		// Only Credential Guard configured; everything else stays null.
		v := computeDeviceGuard(dwordItems(map[string]int64{
			"lsacfgflags": 1,
		}))
		require.NotNil(t, v.credentialGuardConfig)
		assert.Equal(t, int64(1), *v.credentialGuardConfig)
		assert.Nil(t, v.virtualizationBasedSecurityEnabled)
		assert.Nil(t, v.requirePlatformSecurityFeatures)
		assert.Nil(t, v.hypervisorEnforcedCodeIntegrity)
		assert.Nil(t, v.hvciMatRequired)
		assert.Nil(t, v.systemGuardLaunch)
		assert.Nil(t, v.kernelShadowStacksLaunch)
	})
}
