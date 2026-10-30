// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/stretchr/testify/require"
)

func TestGetFirstAvailableLun(t *testing.T) {
	t.Run("no luns available", func(t *testing.T) {
		instanceInfo := &instanceInfo{
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					StorageProfile: &armcompute.StorageProfile{
						DataDisks: []*armcompute.DataDisk{},
					},
				},
			},
		}
		// fill in all available LUNs for the scanner
		for i := range int32(64) {
			instanceInfo.vm.Properties.StorageProfile.DataDisks = append(instanceInfo.vm.Properties.StorageProfile.DataDisks, &armcompute.DataDisk{
				Lun: new(i),
			})
		}

		_, err := instanceInfo.getFirstAvailableLun()
		require.Error(t, err)
	})
	t.Run("first available lun on a scanner with no disks", func(t *testing.T) {
		instanceInfo := instanceInfo{
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					StorageProfile: &armcompute.StorageProfile{
						DataDisks: []*armcompute.DataDisk{},
					},
				},
			},
		}

		lun, err := instanceInfo.getFirstAvailableLun()
		require.NoError(t, err)
		require.Equal(t, 0, lun)
	})
	t.Run("first available lun on a scanner with some disks", func(t *testing.T) {
		instanceInfo := instanceInfo{
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					StorageProfile: &armcompute.StorageProfile{
						DataDisks: []*armcompute.DataDisk{},
					},
				},
			},
		}
		// fill in 15 luns
		for i := range int32(16) {
			instanceInfo.vm.Properties.StorageProfile.DataDisks = append(instanceInfo.vm.Properties.StorageProfile.DataDisks, &armcompute.DataDisk{
				Lun: new(i),
			})
		}

		lun, err := instanceInfo.getFirstAvailableLun()
		require.NoError(t, err)
		require.Equal(t, 16, lun)
	})
}
