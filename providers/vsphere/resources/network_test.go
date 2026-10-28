// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// createSimulatorDvs creates a distributed switch in vcsim's default
// datacenter and returns it with its config and summary read back.
func createSimulatorDvs(t *testing.T, ctx context.Context, c *vim25.Client, spec types.BaseDVSConfigSpec) (*object.DistributedVirtualSwitch, *mo.DistributedVirtualSwitch) {
	t.Helper()
	finder := find.NewFinder(c, true)
	dc, err := finder.DefaultDatacenter(ctx)
	require.NoError(t, err)
	folders, err := dc.Folders(ctx)
	require.NoError(t, err)

	task, err := folders.NetworkFolder.CreateDVS(ctx, types.DVSCreateSpec{ConfigSpec: spec})
	require.NoError(t, err)
	info, err := task.WaitForResult(ctx)
	require.NoError(t, err)
	ref := info.Result.(types.ManagedObjectReference)
	dvs := object.NewDistributedVirtualSwitch(c, ref)

	var mdvs mo.DistributedVirtualSwitch
	require.NoError(t, dvs.Properties(ctx, ref, []string{"config", "summary", "portgroup"}, &mdvs))
	return dvs, &mdvs
}

// Synthetic (vcsim): a distributed switch created through the vSphere API
// with hardening-relevant settings, read back from the simulator.
func TestDvsSettingsFrom_Simulator(t *testing.T) {
	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		_, mdvs := createSimulatorDvs(t, ctx, c, &types.VMwareDVSConfigSpec{
			DVSConfigSpec: types.DVSConfigSpec{
				Name: "dvs-hardening",
				DefaultPortConfig: &types.VMwareDVSPortSetting{
					IpfixEnabled: &types.BoolPolicy{Value: types.NewBool(true)},
					SecurityPolicy: &types.DVSSecurityPolicy{
						AllowPromiscuous: &types.BoolPolicy{Value: types.NewBool(true)},
						MacChanges:       &types.BoolPolicy{Value: types.NewBool(false)},
						ForgedTransmits:  &types.BoolPolicy{Value: types.NewBool(false)},
					},
				},
			},
			MaxMtu: 9000,
			LinkDiscoveryProtocolConfig: &types.LinkDiscoveryProtocolConfig{
				Protocol:  string(types.LinkDiscoveryProtocolConfigProtocolTypeLldp),
				Operation: string(types.LinkDiscoveryProtocolConfigOperationTypeBoth),
			},
			IpfixConfig: &types.VMwareIpfixConfig{CollectorIpAddress: "192.0.2.10", CollectorPort: 2055},
		})

		got := dvsSettingsFrom(mdvs.Config, mdvs.Summary.ProductInfo)
		require.NotNil(t, got.maxMtu)
		assert.Equal(t, int32(9000), *got.maxMtu)
		require.NotNil(t, got.linkDiscoveryProtocol)
		assert.Equal(t, "lldp", *got.linkDiscoveryProtocol)
		require.NotNil(t, got.linkDiscoveryOperation)
		assert.Equal(t, "both", *got.linkDiscoveryOperation)
		require.NotNil(t, got.netflowEnabled)
		assert.True(t, *got.netflowEnabled)
		require.NotNil(t, got.netflowCollectorIp)
		assert.Equal(t, "192.0.2.10", *got.netflowCollectorIp)
		require.NotNil(t, got.defaultSecurityPolicy)
		assert.True(t, boolPolicyValue(got.defaultSecurityPolicy.AllowPromiscuous))
		assert.False(t, boolPolicyValue(got.defaultSecurityPolicy.MacChanges))

		// vcsim stores the product info on the summary only, which exercises
		// the fallback; it reports the simulated vCenter's own version.
		require.NotNil(t, got.version)
		assert.Equal(t, c.ServiceContent.About.Version, *got.version)

		// vcsim keeps no health check configuration from the create spec.
		require.NotNil(t, got.healthCheckEnabled)
		assert.False(t, *got.healthCheckEnabled)
	})
}

// Synthetic: switch configurations no simulator run produced.
func TestDvsSettingsFrom_Synthetic(t *testing.T) {
	t.Run("no config leaves every field null", func(t *testing.T) {
		got := dvsSettingsFrom(nil, nil)
		assert.Nil(t, got.version)
		assert.Nil(t, got.maxMtu)
		assert.Nil(t, got.linkDiscoveryProtocol)
		assert.Nil(t, got.linkDiscoveryOperation)
		assert.Nil(t, got.netflowEnabled)
		assert.Nil(t, got.netflowCollectorIp)
		assert.Nil(t, got.healthCheckEnabled)
		assert.Nil(t, got.defaultSecurityPolicy)
	})

	t.Run("config product version wins over the summary", func(t *testing.T) {
		cfg := &types.VMwareDVSConfigInfo{DVSConfigInfo: types.DVSConfigInfo{
			ProductInfo: types.DistributedVirtualSwitchProductSpec{Version: "8.0.3"},
		}}
		got := dvsSettingsFrom(cfg, &types.DistributedVirtualSwitchProductSpec{Version: "7.0.0"})
		require.NotNil(t, got.version)
		assert.Equal(t, "8.0.3", *got.version)
	})

	t.Run("one enabled health check is enough", func(t *testing.T) {
		cfg := &types.VMwareDVSConfigInfo{DVSConfigInfo: types.DVSConfigInfo{
			HealthCheckConfig: []types.BaseDVSHealthCheckConfig{
				&types.VMwareDVSVlanMtuHealthCheckConfig{VMwareDVSHealthCheckConfig: types.VMwareDVSHealthCheckConfig{
					DVSHealthCheckConfig: types.DVSHealthCheckConfig{Enable: types.NewBool(false), Interval: 1},
				}},
				&types.VMwareDVSTeamingHealthCheckConfig{VMwareDVSHealthCheckConfig: types.VMwareDVSHealthCheckConfig{
					DVSHealthCheckConfig: types.DVSHealthCheckConfig{Enable: types.NewBool(true), Interval: 1},
				}},
			},
		}}
		got := dvsSettingsFrom(cfg, nil)
		require.NotNil(t, got.healthCheckEnabled)
		assert.True(t, *got.healthCheckEnabled)
	})

	t.Run("health checks that are all disabled or unset read false", func(t *testing.T) {
		cfg := &types.VMwareDVSConfigInfo{DVSConfigInfo: types.DVSConfigInfo{
			HealthCheckConfig: []types.BaseDVSHealthCheckConfig{
				&types.VMwareDVSVlanMtuHealthCheckConfig{VMwareDVSHealthCheckConfig: types.VMwareDVSHealthCheckConfig{
					DVSHealthCheckConfig: types.DVSHealthCheckConfig{Enable: types.NewBool(false)},
				}},
				&types.VMwareDVSTeamingHealthCheckConfig{},
			},
		}}
		got := dvsSettingsFrom(cfg, nil)
		require.NotNil(t, got.healthCheckEnabled)
		assert.False(t, *got.healthCheckEnabled)
	})

	t.Run("missing link discovery and netflow config is null", func(t *testing.T) {
		got := dvsSettingsFrom(&types.VMwareDVSConfigInfo{MaxMtu: 1500}, nil)
		require.NotNil(t, got.maxMtu)
		assert.Equal(t, int32(1500), *got.maxMtu)
		assert.Nil(t, got.linkDiscoveryProtocol)
		assert.Nil(t, got.linkDiscoveryOperation)
		assert.Nil(t, got.netflowCollectorIp)
		assert.Nil(t, got.netflowEnabled)
		assert.Nil(t, got.version)
	})

	t.Run("a non-VMware switch config reports no VMware-only fields", func(t *testing.T) {
		got := dvsSettingsFrom(&types.DVSConfigInfo{}, nil)
		assert.Nil(t, got.maxMtu)
		assert.Nil(t, got.linkDiscoveryProtocol)
		require.NotNil(t, got.healthCheckEnabled)
		assert.False(t, *got.healthCheckEnabled)
	})
}
