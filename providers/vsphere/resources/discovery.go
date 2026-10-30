// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discovery Flags
const (
	DiscoveryAll  = "all"  // api, hosts, instances
	DiscoveryAuto = "auto" // api, hosts

	DiscoveryApi          = "api"
	DiscoveryInstances    = "instances"
	DiscoveryHostMachines = "host-machines"
)

var All = []string{
	DiscoveryApi,
	DiscoveryHostMachines,
	DiscoveryInstances,
}

var Auto = []string{
	DiscoveryApi,
	DiscoveryHostMachines,
}

func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.VsphereConnection)

	asset := conn.Asset()
	if asset == nil {
		return nil, nil
	}

	// if the asset is not a vsphere asset, return nil
	if asset.Platform == nil {
		return nil, nil
	}

	// we only run discovery on vSphere API assets
	if asset.Platform.Name != connection.VspherePlatform {
		return nil, nil
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conn.Conf.Discover.Targets)

	res, err := NewResource(runtime, "vsphere", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	vsphereResource := res.(*mqlVsphere)

	datacenterList := vsphereResource.GetDatacenters()
	if datacenterList.Error != nil {
		return nil, datacenterList.Error
	}

	for i := range datacenterList.Data {
		datacenterResource := datacenterList.Data[i].(*mqlVsphereDatacenter)
		for i := range targets {
			target := targets[i]
			list, err := discoverDatacenter(conn, datacenterResource, target)
			if err != nil {
				log.Error().Err(err).Msg("error during discovery")
				continue
			}
			in.Spec.Assets = append(in.Spec.Assets, list...)
		}
	}

	return in, nil
}

func handleTargets(targets []string) []string {
	if len(targets) == 0 || stringx.Contains(targets, DiscoveryAuto) {
		// default to auto if none defined
		return Auto
	}
	if stringx.Contains(targets, DiscoveryAll) {
		return All
	}
	return targets
}

func discoverDatacenter(conn *connection.VsphereConnection, datacenterResource *mqlVsphereDatacenter, target string) ([]*inventory.Asset, error) {
	assetList := []*inventory.Asset{}

	instanceUuid, err := conn.InstanceUUID()
	if err != nil {
		return nil, err
	}

	// resolve esxi hosts
	switch target {
	case DiscoveryHostMachines:
		hostList := datacenterResource.GetHosts()
		if hostList.Error != nil {
			return nil, hostList.Error
		}
		for j := range hostList.Data {
			mqlHost := hostList.Data[j].(*mqlVsphereHost)

			esxiVersion, err := conn.EsxiVersion(mqlHost.Moid.Data)
			if err != nil {
				log.Error().Err(err).Str("host", mqlHost.Moid.Data).Msg("failed to get version of esxi host")
				continue
			}

			platformID := connection.VsphereResourceID(instanceUuid, mqlHost.Moid.Data)
			clonedConfig := conn.Conf.Clone(inventory.WithoutDiscovery())
			clonedConfig.PlatformId = platformID

			labels := map[string]string{
				"vsphere.vmware.com/name":          mqlHost.Name.Data,
				"vsphere.vmware.com/moid":          mqlHost.Moid.Data,
				"vsphere.vmware.com/inventorypath": mqlHost.InventoryPath.Data,
			}

			// Add tags as labels with vsphere.vmware.com/tag/ prefix
			if mqlHost.Tags.Error == nil {
				for _, tag := range mqlHost.Tags.Data {
					if tagStr, ok := tag.(string); ok {
						labels["vsphere.vmware.com/tag/"+tagStr] = "true"
					}
				}
			}

			hostPlatform := &inventory.Platform{
				Version:               esxiVersion.Version,
				Build:                 esxiVersion.Build,
				TechnologyUrlSegments: []string{"vmware", "esxi", esxiVersion.Version + "-" + esxiVersion.Build},
			}
			connection.PlatformByName(connection.EsxiPlatform).Apply(hostPlatform)

			assetList = append(assetList, &inventory.Asset{
				Name:        mqlHost.Name.Data,
				Platform:    hostPlatform,
				Connections: []*inventory.Config{clonedConfig}, // pass-in the parent connection config
				Labels:      labels,
				State:       hostPowerState(mqlHost),
				PlatformIds: []string{platformID},
			})
		}
	case DiscoveryInstances:
		vmList := datacenterResource.GetVms()
		if vmList.Error != nil {
			return nil, vmList.Error
		}
		for j := range vmList.Data {
			vm := vmList.Data[j].(*mqlVsphereVm)

			platformID := connection.VsphereResourceID(instanceUuid, vm.Moid.Data)
			clonedConfig := conn.Conf.Clone(inventory.WithoutDiscovery())
			clonedConfig.PlatformId = platformID

			labels := map[string]string{
				"vsphere.vmware.com/name":           vm.Name.Data,
				"vsphere.vmware.com/moid":           vm.Moid.Data,
				"vsphere.vmware.com/inventory-path": vm.InventoryPath.Data,
			}

			// Add tags as labels with vsphere.vmware.com/tag/ prefix
			if vm.Tags.Error == nil {
				for _, tag := range vm.Tags.Data {
					if tagStr, ok := tag.(string); ok {
						labels["vsphere.vmware.com/tag/"+tagStr] = "true"
					}
				}
			}

			assetList = append(assetList, &inventory.Asset{
				Name:        vm.Name.Data,
				Platform:    &inventory.Platform{},
				Connections: []*inventory.Config{clonedConfig},
				Labels:      labels,
				State:       vmGuestState(vm),
				PlatformIds: []string{platformID},
			})
		}
	}

	return assetList, nil
}

// hostPowerState reports a host's power state for asset discovery, guarding
// against missing cached host data (mqlHost.host is nil when the resource was
// created via initVsphereHost rather than fetched during datacenter
// discovery).
func hostPowerState(mqlHost *mqlVsphereHost) inventory.State {
	if mqlHost == nil || mqlHost.host == nil {
		return inventory.State_STATE_UNKNOWN
	}
	return mapHostPowerstateToState(mqlHost.host.Runtime.PowerState)
}

// vmGuestState reports a VM's guest power state for asset discovery, guarding
// against the VM having no Guest info (templates, suspended VMs, VMs without
// VMware Tools all leave Guest nil).
func vmGuestState(vm *mqlVsphereVm) inventory.State {
	if vm == nil || vm.vm == nil || vm.vm.Guest == nil {
		return inventory.State_STATE_UNKNOWN
	}
	return mapVmGuestState(vm.vm.Guest.GuestState)
}

func mapHostPowerstateToState(hostPowerState types.HostSystemPowerState) inventory.State {
	switch hostPowerState {
	case types.HostSystemPowerStatePoweredOn:
		return inventory.State_STATE_RUNNING
	case types.HostSystemPowerStatePoweredOff:
		return inventory.State_STATE_STOPPED
	case types.HostSystemPowerStateStandBy:
		return inventory.State_STATE_PENDING
	case types.HostSystemPowerStateUnknown:
		return inventory.State_STATE_UNKNOWN
	default:
		return inventory.State_STATE_UNKNOWN
	}
}

func mapVmGuestState(vsphereGuestState string) inventory.State {
	switch types.VirtualMachineGuestState(vsphereGuestState) {
	case types.VirtualMachineGuestStateRunning:
		return inventory.State_STATE_RUNNING
	case types.VirtualMachineGuestStateShuttingDown:
		return inventory.State_STATE_STOPPING
	case types.VirtualMachineGuestStateResetting:
		return inventory.State_STATE_REBOOT
	case types.VirtualMachineGuestStateStandby:
		return inventory.State_STATE_PENDING
	case types.VirtualMachineGuestStateNotRunning:
		return inventory.State_STATE_STOPPED
	case types.VirtualMachineGuestStateUnknown:
		return inventory.State_STATE_UNKNOWN
	default:
		return inventory.State_STATE_UNKNOWN
	}
}
