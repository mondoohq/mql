// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/simulator/esx"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/types"
)

// Synthetic (vcsim): a simulator VM reconfigured through the vSphere API and
// read back from it.
func TestVmConfigSettingsFrom_Simulator(t *testing.T) {
	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		finder := find.NewFinder(c, true)
		dc, err := finder.DefaultDatacenter(ctx)
		require.NoError(t, err)
		finder.SetDatacenter(dc)
		vms, err := finder.VirtualMachineList(ctx, "*")
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(vms), 2)
		vm, plainVm := vms[0], vms[1]

		task, err := vm.Reconfigure(ctx, types.VirtualMachineConfigSpec{
			GuestId:           "ubuntu64Guest",
			MigrateEncryption: string(types.VirtualMachineConfigSpecEncryptedVMotionModesRequired),
			FtEncryptionMode:  string(types.VirtualMachineConfigSpecEncryptedFtModesFtEncryptionRequired),
			Flags:             &types.VirtualMachineFlagInfo{EnableLogging: types.NewBool(false)},
			Tools:             &types.ToolsConfigInfo{ToolsUpgradePolicy: string(types.UpgradePolicyUpgradeAtPowerCycle)},
		})
		require.NoError(t, err)
		require.NoError(t, task.Wait(ctx))

		got := vmConfigSettingsFrom(fetchSimulatorVmConfig(t, ctx, vm))
		require.NotNil(t, got.hardwareVersion)
		assert.Equal(t, esx.HardwareVersion, *got.hardwareVersion)
		require.NotNil(t, got.guestId)
		assert.Equal(t, "ubuntu64Guest", *got.guestId)
		require.NotNil(t, got.migrateEncryption)
		assert.Equal(t, "required", *got.migrateEncryption)
		require.NotNil(t, got.ftEncryptionMode)
		assert.Equal(t, "ftEncryptionRequired", *got.ftEncryptionMode)
		require.NotNil(t, got.loggingEnabled)
		assert.False(t, *got.loggingEnabled)
		require.NotNil(t, got.toolsUpgradePolicy)
		assert.Equal(t, "upgradeAtPowerCycle", *got.toolsUpgradePolicy)

		// The other VM was not reconfigured, so the encryption modes it never
		// set read as empty rather than borrowing the first VM's values.
		plain := vmConfigSettingsFrom(fetchSimulatorVmConfig(t, ctx, plainVm))
		require.NotNil(t, plain.migrateEncryption)
		assert.Equal(t, "", *plain.migrateEncryption)
		require.NotNil(t, plain.hardwareVersion)
		assert.Equal(t, esx.HardwareVersion, *plain.hardwareVersion)
	})
}

// Synthetic: configuration shapes no simulator run produced.
func TestVmConfigSettingsFrom_Synthetic(t *testing.T) {
	t.Run("no config leaves every field null", func(t *testing.T) {
		got := vmConfigSettingsFrom(nil)
		assert.Nil(t, got.hardwareVersion)
		assert.Nil(t, got.guestId)
		assert.Nil(t, got.migrateEncryption)
		assert.Nil(t, got.ftEncryptionMode)
		assert.Nil(t, got.loggingEnabled)
		assert.Nil(t, got.toolsUpgradePolicy)
	})

	t.Run("unreported logging flag is null, not false", func(t *testing.T) {
		got := vmConfigSettingsFrom(&types.VirtualMachineConfigInfo{Version: "vmx-21"})
		assert.Nil(t, got.loggingEnabled)
		require.NotNil(t, got.hardwareVersion)
		assert.Equal(t, "vmx-21", *got.hardwareVersion)
	})

	t.Run("logging enabled reads true", func(t *testing.T) {
		got := vmConfigSettingsFrom(&types.VirtualMachineConfigInfo{
			Flags: types.VirtualMachineFlagInfo{EnableLogging: types.NewBool(true)},
		})
		require.NotNil(t, got.loggingEnabled)
		assert.True(t, *got.loggingEnabled)
	})

	t.Run("no tools config reads an empty upgrade policy", func(t *testing.T) {
		got := vmConfigSettingsFrom(&types.VirtualMachineConfigInfo{})
		require.NotNil(t, got.toolsUpgradePolicy)
		assert.Equal(t, "", *got.toolsUpgradePolicy)
	})
}
