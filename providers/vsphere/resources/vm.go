// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/providers/vsphere/resources/resourceclient"
)

type mqlVsphereVmInternal struct {
	vm     *mo.VirtualMachine
	vmOnce sync.Once
}

func (v *mqlVsphereVm) setVm(m *mo.VirtualMachine) {
	v.vmOnce.Do(func() {
		v.vm = m
	})
}

func (v *mqlVsphereVm) id() (string, error) {
	return v.Moid.Data, nil
}

func (v *mqlVsphereVm) advancedSettings() (map[string]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	vClient := getClientInstance(conn)

	if v.InventoryPath.Error != nil {
		return nil, v.InventoryPath.Error
	}
	path := v.InventoryPath.Data

	vm, err := vClient.VirtualMachineByInventoryPath(path)
	if err != nil {
		return nil, err
	}

	return resourceclient.AdvancedSettings(vm)
}

// kmsCluster resolves the typed vsphere.kmsCluster providing this VM's
// encryption key via the kmsClusters map on the cached inventory; null when
// the VM isn't encrypted or the provider isn't in the registered list.
func (v *mqlVsphereVm) kmsCluster() (*mqlVsphereKmsCluster, error) {
	if v.vm == nil || v.vm.Config == nil || v.vm.Config.KeyId == nil || v.vm.Config.KeyId.ProviderId == nil {
		v.KmsCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	providerId := v.vm.Config.KeyId.ProviderId.Id
	if providerId == "" {
		v.KmsCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if cluster, ok := inv.kmsClusters[providerId]; ok {
		return cluster, nil
	}
	v.KmsCluster.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// vmConfigSettings holds scalar VM configuration fields read from
// VirtualMachineConfigInfo. A nil pointer means vCenter did not report the
// value, which surfaces as null rather than an invented default.
type vmConfigSettings struct {
	hardwareVersion    *string
	guestId            *string
	migrateEncryption  *string
	ftEncryptionMode   *string
	loggingEnabled     *bool
	toolsUpgradePolicy *string
}

func vmConfigSettingsFrom(cfg *types.VirtualMachineConfigInfo) vmConfigSettings {
	if cfg == nil {
		return vmConfigSettings{}
	}
	toolsUpgradePolicy := ""
	if cfg.Tools != nil {
		toolsUpgradePolicy = cfg.Tools.ToolsUpgradePolicy
	}
	return vmConfigSettings{
		hardwareVersion:    &cfg.Version,
		guestId:            &cfg.GuestId,
		migrateEncryption:  &cfg.MigrateEncryption,
		ftEncryptionMode:   &cfg.FtEncryptionMode,
		loggingEnabled:     cfg.Flags.EnableLogging,
		toolsUpgradePolicy: &toolsUpgradePolicy,
	}
}
