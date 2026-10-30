// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"context"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

type instanceInfo struct {
	subscriptionId string
	resourceGroup  string
	instanceName   string
	location       string
	bootDiskId     string
	zones          []*string
	// Attach the entire VM response as well
	vm compute.VirtualMachine
}

func (s *instanceInfo) getFirstAvailableLun() (int, error) {
	takenLuns := []int{}

	if s.vm.Properties.StorageProfile == nil {
		return 0, errors.New("instance storage profile not found")
	}
	if s.vm.Properties.StorageProfile.DataDisks == nil {
		return 0, errors.New("instance data disks not found")
	}

	for _, disk := range s.vm.Properties.StorageProfile.DataDisks {
		takenLuns = append(takenLuns, int(*disk.Lun))
	}

	availableLuns := []int{}
	for i := range 64 {
		// exclude the taken LUNs
		available := !slices.Contains(takenLuns, i)
		if available {
			availableLuns = append(availableLuns, i)
		} else {
			// log just for visibility
			log.Debug().Int("LUN", i).Msg("azure snapshot> LUN is taken, skipping")
		}
	}
	if len(availableLuns) == 0 {
		return 0, errors.New("no available LUNs")
	}
	return availableLuns[0], nil
}

func GetInstanceInfo(resourceGroup, instanceName, subId string, token azcore.TokenCredential) (instanceInfo, error) {
	ctx := context.Background()
	ii := instanceInfo{}

	computeSvc, err := computeClient(token, subId, nil)
	if err != nil {
		return ii, err
	}

	instance, err := computeSvc.Get(ctx, resourceGroup, instanceName, &compute.VirtualMachinesClientGetOptions{})
	if err != nil {
		return ii, err
	}
	ii.resourceGroup = resourceGroup
	ii.instanceName = *instance.Name
	ii.bootDiskId = *instance.Properties.StorageProfile.OSDisk.ManagedDisk.ID
	ii.location = *instance.Location
	ii.subscriptionId = subId
	ii.zones = instance.Zones
	ii.vm = instance.VirtualMachine
	return ii, nil
}
