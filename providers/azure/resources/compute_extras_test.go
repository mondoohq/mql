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
