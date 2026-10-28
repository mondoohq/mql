// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// Synthetic (vcsim): port groups created through the vSphere API on a
// simulator distributed switch and read back from it.
func TestDvPortgroupSettingsFrom_Simulator(t *testing.T) {
	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		dvs, _ := createSimulatorDvs(t, ctx, c, &types.VMwareDVSConfigSpec{
			DVSConfigSpec: types.DVSConfigSpec{Name: "dvs-pg"},
		})

		task, err := dvs.AddPortgroup(ctx, []types.DVPortgroupConfigSpec{{
			Name:     "pg-ephemeral",
			Type:     string(types.DistributedVirtualPortgroupPortgroupTypeEphemeral),
			NumPorts: 8,
			DefaultPortConfig: &types.VMwareDVSPortSetting{
				DVPortSetting: types.DVPortSetting{Blocked: &types.BoolPolicy{Value: types.NewBool(true)}},
				Vlan: &types.VmwareDistributedVirtualSwitchTrunkVlanSpec{
					VlanId: []types.NumericRange{{Start: 100, End: 200}, {Start: 300, End: 300}},
				},
			},
			Policy: &types.VMwareDVSPortgroupPolicy{
				SecurityPolicyOverrideAllowed: true,
				VlanOverrideAllowed:           true,
				UplinkTeamingOverrideAllowed:  false,
				MacManagementOverrideAllowed:  types.NewBool(true),
			},
		}})
		require.NoError(t, err)
		require.NoError(t, task.Wait(ctx))

		var mdvs mo.DistributedVirtualSwitch
		require.NoError(t, dvs.Properties(ctx, dvs.Reference(), []string{"portgroup"}, &mdvs))

		byName := map[string]dvPortgroupSettings{}
		for _, ref := range mdvs.Portgroup {
			var pg mo.DistributedVirtualPortgroup
			require.NoError(t, dvs.Properties(ctx, ref, []string{"config"}, &pg))
			byName[pg.Config.Name] = dvPortgroupSettingsFrom(&pg.Config)
		}

		got, ok := byName["pg-ephemeral"]
		require.True(t, ok)
		assert.Equal(t, "ephemeral", got.portBinding)
		require.NotNil(t, got.blocked)
		assert.True(t, *got.blocked)
		assert.Equal(t, []string{"100-200", "300-300"}, got.vlanTrunkRanges)
		require.NotNil(t, got.securityPolicyOverrideAllowed)
		assert.True(t, *got.securityPolicyOverrideAllowed)
		require.NotNil(t, got.vlanOverrideAllowed)
		assert.True(t, *got.vlanOverrideAllowed)
		require.NotNil(t, got.uplinkTeamingOverrideAllowed)
		assert.False(t, *got.uplinkTeamingOverrideAllowed)
		require.NotNil(t, got.macManagementOverrideAllowed)
		assert.True(t, *got.macManagementOverrideAllowed)

		// vcsim creates the uplink port group with an earlyBinding trunk of
		// every VLAN and its default policy, which leaves the MAC management
		// override unset.
		var uplink *dvPortgroupSettings
		for name, s := range byName {
			if name != "pg-ephemeral" {
				uplink = &s
			}
		}
		require.NotNil(t, uplink)
		assert.Equal(t, "earlyBinding", uplink.portBinding)
		assert.Equal(t, []string{"0-4094"}, uplink.vlanTrunkRanges)
		assert.Nil(t, uplink.blocked)
		assert.Nil(t, uplink.macManagementOverrideAllowed)
		require.NotNil(t, uplink.securityPolicyOverrideAllowed)
		assert.False(t, *uplink.securityPolicyOverrideAllowed)
	})
}

// Synthetic: port group configurations no simulator run produced.
func TestDvPortgroupSettingsFrom_Synthetic(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		got := dvPortgroupSettingsFrom(nil)
		assert.Equal(t, "", got.portBinding)
		assert.Empty(t, got.vlanTrunkRanges)
		assert.Nil(t, got.blocked)
		assert.Nil(t, got.securityPolicyOverrideAllowed)
	})

	t.Run("single VLAN tag has no trunk ranges", func(t *testing.T) {
		got := dvPortgroupSettingsFrom(&types.DVPortgroupConfigInfo{
			Type: "earlyBinding",
			DefaultPortConfig: &types.VMwareDVSPortSetting{
				Vlan: &types.VmwareDistributedVirtualSwitchVlanIdSpec{VlanId: 42},
			},
		})
		assert.Empty(t, got.vlanTrunkRanges)
	})

	t.Run("blocked false reads false, not null", func(t *testing.T) {
		got := dvPortgroupSettingsFrom(&types.DVPortgroupConfigInfo{
			DefaultPortConfig: &types.VMwareDVSPortSetting{
				DVPortSetting: types.DVPortSetting{Blocked: &types.BoolPolicy{Value: types.NewBool(false)}},
			},
		})
		require.NotNil(t, got.blocked)
		assert.False(t, *got.blocked)
	})

	t.Run("a non-VMware policy leaves the override fields null", func(t *testing.T) {
		got := dvPortgroupSettingsFrom(&types.DVPortgroupConfigInfo{
			Policy: &types.DVPortgroupPolicy{BlockOverrideAllowed: true},
		})
		assert.Nil(t, got.securityPolicyOverrideAllowed)
		assert.Nil(t, got.vlanOverrideAllowed)
		assert.Nil(t, got.uplinkTeamingOverrideAllowed)
		assert.Nil(t, got.macManagementOverrideAllowed)
	})
}
