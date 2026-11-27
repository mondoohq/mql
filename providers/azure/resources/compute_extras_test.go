// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/stretchr/testify/assert"
)

func TestVmOsType(t *testing.T) {
	t.Run("nil properties returns nil", func(t *testing.T) {
		assert.Nil(t, vmOsType(nil))
	})
	t.Run("nil storage profile returns nil", func(t *testing.T) {
		assert.Nil(t, vmOsType(&compute.VirtualMachineProperties{}))
	})
	t.Run("nil os disk returns nil", func(t *testing.T) {
		props := &compute.VirtualMachineProperties{StorageProfile: &compute.StorageProfile{}}
		assert.Nil(t, vmOsType(props))
	})
	t.Run("linux os type", func(t *testing.T) {
		linux := compute.OperatingSystemTypesLinux
		props := &compute.VirtualMachineProperties{
			StorageProfile: &compute.StorageProfile{
				OSDisk: &compute.OSDisk{OSType: &linux},
			},
		}
		got := vmOsType(props)
		assert.NotNil(t, got)
		assert.Equal(t, "Linux", *got)
	})
}

func TestVmPlacementFields(t *testing.T) {
	t.Run("nil properties leaves every field unset", func(t *testing.T) {
		// Synthetic: a VM record without properties; no target showed this.
		got := vmPlacementFields(nil)
		assert.Nil(t, got.vmSize)
		assert.Nil(t, got.priority)
		assert.Nil(t, got.evictionPolicy)
		assert.Empty(t, got.dedicatedHostID)
		assert.Empty(t, got.dedicatedHostGroupID)
	})
	t.Run("spot VM on a dedicated host", func(t *testing.T) {
		// Synthetic: covers every field at once; a Spot VM cannot actually
		// run on a dedicated host.
		hostID := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/hostGroups/hg/hosts/h1"
		groupID := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/hostGroups/hg"
		got := vmPlacementFields(&compute.VirtualMachineProperties{
			HardwareProfile: &compute.HardwareProfile{VMSize: ptr(compute.VirtualMachineSizeTypesStandardB1S)},
			Priority:        ptr(compute.VirtualMachinePriorityTypesSpot),
			EvictionPolicy:  ptr(compute.VirtualMachineEvictionPolicyTypesDeallocate),
			Host:            &compute.SubResource{ID: &hostID},
			HostGroup:       &compute.SubResource{ID: &groupID},
		})
		assert.Equal(t, "Standard_B1s", *got.vmSize)
		assert.Equal(t, "Spot", *got.priority)
		assert.Equal(t, "Deallocate", *got.evictionPolicy)
		assert.Equal(t, hostID, got.dedicatedHostID)
		assert.Equal(t, groupID, got.dedicatedHostGroupID)
	})
	t.Run("regular VM has no eviction policy", func(t *testing.T) {
		// Synthetic: a pay-as-you-go VM reports no eviction policy.
		got := vmPlacementFields(&compute.VirtualMachineProperties{
			Priority: ptr(compute.VirtualMachinePriorityTypesRegular),
		})
		assert.Equal(t, "Regular", *got.priority)
		assert.Nil(t, got.evictionPolicy)
		assert.Nil(t, got.vmSize)
	})
}

func TestDedicatedHostGroupIDFromHostID(t *testing.T) {
	// Synthetic: ARM ID shapes; no target showed these.
	assert.Equal(t,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/hostGroups/hg",
		dedicatedHostGroupIDFromHostID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/hostGroups/hg/hosts/h1"))
	// ARM IDs are case-insensitive, and the casing of the segment varies.
	assert.Equal(t,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/HOSTGROUPS/hg",
		dedicatedHostGroupIDFromHostID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/HOSTGROUPS/hg/Hosts/h1"))
	assert.Empty(t, dedicatedHostGroupIDFromHostID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/hostGroups/hg"))
	assert.Empty(t, dedicatedHostGroupIDFromHostID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/hostGroups/hg/hosts/"))
	assert.Empty(t, dedicatedHostGroupIDFromHostID(""))
}
