// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	hybridcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute/v3"
	"github.com/stretchr/testify/assert"
)

func TestHybridMachineManagementFields(t *testing.T) {
	t.Run("nil machine", func(t *testing.T) {
		// Synthetic: no target showed this.
		got := hybridMachineManagementFields(nil)
		assert.Nil(t, got.kind)
		assert.Nil(t, got.principalID)
		assert.Nil(t, got.patchMode)
		assert.Nil(t, got.mssqlDiscovered)
	})
	t.Run("windows machine with patch settings and identity", func(t *testing.T) {
		// Synthetic: covers the Windows patch settings path, the agent's
		// string-encoded SQL discovery flag, and the identity block.
		got := hybridMachineManagementFields(&hybridcompute.Machine{
			Kind: ptr(hybridcompute.ArcKindEnumAWS),
			Identity: &hybridcompute.ManagedServiceIdentity{
				Type:        ptr(hybridcompute.ManagedServiceIdentityTypeSystemAssigned),
				PrincipalID: ptr("00000000-0000-0000-0000-000000000001"),
				TenantID:    ptr("00000000-0000-0000-0000-000000000002"),
			},
			Properties: &hybridcompute.MachineProperties{
				MssqlDiscovered: ptr("true"),
				AgentUpgrade:    &hybridcompute.AgentUpgrade{EnableAutomaticUpgrade: ptr(true)},
				OSProfile: &hybridcompute.OSProfile{
					WindowsConfiguration: &hybridcompute.OSProfileWindowsConfiguration{
						PatchSettings: &hybridcompute.PatchSettings{
							PatchMode:         ptr(hybridcompute.PatchModeTypesAutomaticByPlatform),
							AssessmentMode:    ptr(hybridcompute.AssessmentModeTypesAutomaticByPlatform),
							EnableHotpatching: ptr(true),
						},
					},
				},
			},
		})
		assert.Equal(t, "AWS", *got.kind)
		assert.Equal(t, "SystemAssigned", *got.identityType)
		assert.Equal(t, "00000000-0000-0000-0000-000000000001", *got.principalID)
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", *got.tenantID)
		assert.Equal(t, "AutomaticByPlatform", *got.patchMode)
		assert.Equal(t, "AutomaticByPlatform", *got.assessmentMode)
		assert.True(t, *got.hotpatchEnabled)
		assert.True(t, *got.agentAutoUpgradeEnabled)
		assert.True(t, *got.mssqlDiscovered)
	})
	t.Run("linux machine reads the linux patch settings", func(t *testing.T) {
		// Synthetic: a Linux machine carries its patch settings under the
		// Linux configuration, with an empty Windows configuration block.
		got := hybridMachineManagementFields(&hybridcompute.Machine{
			Properties: &hybridcompute.MachineProperties{
				MssqlDiscovered: ptr("false"),
				OSProfile: &hybridcompute.OSProfile{
					WindowsConfiguration: &hybridcompute.OSProfileWindowsConfiguration{},
					LinuxConfiguration: &hybridcompute.OSProfileLinuxConfiguration{
						PatchSettings: &hybridcompute.PatchSettings{
							PatchMode:      ptr(hybridcompute.PatchModeTypesImageDefault),
							AssessmentMode: ptr(hybridcompute.AssessmentModeTypesImageDefault),
						},
					},
				},
			},
		})
		assert.Nil(t, got.kind)
		assert.Equal(t, "ImageDefault", *got.patchMode)
		assert.Equal(t, "ImageDefault", *got.assessmentMode)
		assert.Nil(t, got.hotpatchEnabled)
		assert.Nil(t, got.agentAutoUpgradeEnabled)
		assert.False(t, *got.mssqlDiscovered)
	})
}
