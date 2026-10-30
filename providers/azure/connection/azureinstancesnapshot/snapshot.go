// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
)

const (
	createdByLabel = "created-by"
	createdValue   = "cnspec"
)

type snapshotCreator struct {
	subscriptionId string
	token          azcore.TokenCredential
	opts           *policy.ClientOptions
	labels         map[string]*string
}

type snapshotInfo struct {
	snapshotName string
	snapshotId   string
	location     string
}

type diskInfo struct {
	diskName string
	diskId   string
	location string
}

func NewSnapshotCreator(token azcore.TokenCredential, subscriptionId string) (*snapshotCreator, error) {
	createdByVal := createdValue
	sc := &snapshotCreator{
		labels: map[string]*string{
			createdByLabel: &createdByVal,
		},
		token:          token,
		subscriptionId: subscriptionId,
	}
	return sc, nil
}

func (sc *snapshotCreator) snapshotClient() (*compute.SnapshotsClient, error) {
	return compute.NewSnapshotsClient(sc.subscriptionId, sc.token, sc.opts)
}

func (sc *snapshotCreator) diskClient() (*compute.DisksClient, error) {
	return compute.NewDisksClient(sc.subscriptionId, sc.token, sc.opts)
}

func (sc *snapshotCreator) computeClient() (*compute.VirtualMachinesClient, error) {
	return computeClient(sc.token, sc.subscriptionId, sc.opts)
}

func computeClient(token azcore.TokenCredential, subId string, opts *policy.ClientOptions) (*compute.VirtualMachinesClient, error) {
	return compute.NewVirtualMachinesClient(subId, token, opts)
}

func (sc *snapshotCreator) instanceInfo(resourceGroup, instanceName string) (instanceInfo, error) {
	return GetInstanceInfo(resourceGroup, instanceName, sc.subscriptionId, sc.token)
}

func (sc *snapshotCreator) snapshotInfo(resourceGroup, snapshotName string) (snapshotInfo, error) {
	ctx := context.Background()
	si := snapshotInfo{}

	snapshotSvc, err := sc.snapshotClient()
	if err != nil {
		return si, err
	}

	snapshot, err := snapshotSvc.Get(ctx, resourceGroup, snapshotName, &compute.SnapshotsClientGetOptions{})
	if err != nil {
		return si, err
	}

	si.snapshotName = *snapshot.Name
	si.snapshotId = *snapshot.ID
	si.location = *snapshot.Location
	return si, nil
}

func (sc *snapshotCreator) diskInfo(resourceGroup, snapshotName string) (diskInfo, error) {
	ctx := context.Background()
	di := diskInfo{}

	snapshotSvc, err := sc.diskClient()
	if err != nil {
		return di, err
	}

	disk, err := snapshotSvc.Get(ctx, resourceGroup, snapshotName, &compute.DisksClientGetOptions{})
	if err != nil {
		return di, err
	}

	di.diskId = *disk.ID
	di.diskName = *disk.Name
	di.location = *disk.Location
	return di, nil
}

// createDisk creates a new disk
func (sc *snapshotCreator) createDisk(disk compute.Disk, resourceGroupName, diskName string) (compute.Disk, error) {
	ctx := context.Background()

	diskSvc, err := sc.diskClient()
	if err != nil {
		return compute.Disk{}, err
	}

	poller, err := diskSvc.BeginCreateOrUpdate(ctx, resourceGroupName, diskName, disk, &compute.DisksClientBeginCreateOrUpdateOptions{})
	if err != nil {
		return compute.Disk{}, err
	}
	resp, err := poller.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{
		Frequency: 5 * time.Second,
	})
	if err != nil {
		return compute.Disk{}, err
	}
	return resp.Disk, nil
}

// createSnapshotDisk creates a new disk from a snapshot
func (sc *snapshotCreator) createSnapshotDisk(sourceSnapshotId, resourceGroupName, diskName, location string, zones []*string) (compute.Disk, error) {
	// create a new disk from snapshot
	createOpt := compute.DiskCreateOptionCopy
	disk := compute.Disk{
		Location: &location,
		Zones:    zones,
		Name:     &diskName,
		Properties: &compute.DiskProperties{
			CreationData: &compute.CreationData{
				SourceResourceID: &sourceSnapshotId,
				CreateOption:     &createOpt,
			},
		},
		Tags: sc.labels,
	}
	return sc.createDisk(disk, resourceGroupName, diskName)
}

// cloneDisk clones a provided disk
func (sc *snapshotCreator) cloneDisk(sourceDiskId, resourceGroupName, diskName string, location string, zones []*string) (compute.Disk, error) {
	// create a new disk by copying another disk
	createOpt := compute.DiskCreateOptionCopy
	disk := compute.Disk{
		Location: &location,
		Zones:    zones,
		Name:     &diskName,
		Properties: &compute.DiskProperties{
			CreationData: &compute.CreationData{
				SourceResourceID: &sourceDiskId,
				CreateOption:     &createOpt,
			},
		},
		Tags: sc.labels,
	}
	return sc.createDisk(disk, resourceGroupName, diskName)
}

// attachDisk attaches a disk to an instance
func (sc *snapshotCreator) attachDisk(targetInstance instanceInfo, diskName, diskId string, lun int) error {
	ctx := context.Background()
	log.Debug().Str("disk-name", diskName).Int("LUN", lun).Msg("attach disk")
	computeSvc, err := sc.computeClient()
	if err != nil {
		return err
	}
	newDisks := []*compute.DataDisk{}
	// the Azure API requires all disks to be specified, even the already attached ones.
	// we simply attach the new disk to the end of the already present list of data disks
	newDisks = append(newDisks, targetInstance.vm.Properties.StorageProfile.DataDisks...)
	newDisks = append(newDisks, &compute.DataDisk{
		Name:         &diskName,
		CreateOption: to.Ptr(compute.DiskCreateOptionTypesAttach),
		DeleteOption: to.Ptr(compute.DiskDeleteOptionTypesDelete),
		Caching:      to.Ptr(compute.CachingTypesNone),
		Lun:          new(int32(lun)),
		ManagedDisk: &compute.ManagedDiskParameters{
			ID: new(diskId),
		},
	})
	vm := compute.VirtualMachineUpdate{
		Properties: &compute.VirtualMachineProperties{
			StorageProfile: &compute.StorageProfile{
				DataDisks: newDisks,
			},
		},
	}

	poller, err := computeSvc.BeginUpdate(ctx, targetInstance.resourceGroup, targetInstance.instanceName, vm, &compute.VirtualMachinesClientBeginUpdateOptions{})
	if err != nil {
		return err
	}
	start := time.Now()
	for {
		log.Debug().Str("disk-name", diskName).Str("elapsed", time.Duration(time.Since(start)).String()).Msg("polling for disk attach")
		_, err = poller.Poll(ctx)
		if err != nil {
			return err
		}
		if poller.Done() {
			log.Debug().Str("disk-name", diskName).Msg("poller done")
			break
		}
		time.Sleep(5 * time.Second)
	}

	_, err = poller.Result(ctx)
	return err
}

func (sc *snapshotCreator) detachDisk(diskName string, targetInstance instanceInfo) error {
	ctx := context.Background()
	log.Debug().Str("instance-name", targetInstance.instanceName).Msg("detach disk from instance")
	computeSvc, err := sc.computeClient()
	if err != nil {
		return err
	}
	// we stored the disks as they were before attaching the new one in the targetInstance.
	// we simply use that list which will result in the new disk being detached
	vm := compute.VirtualMachineUpdate{
		Properties: &compute.VirtualMachineProperties{
			StorageProfile: &compute.StorageProfile{
				DataDisks: targetInstance.vm.Properties.StorageProfile.DataDisks,
			},
		},
	}

	poller, err := computeSvc.BeginUpdate(ctx, targetInstance.resourceGroup, targetInstance.instanceName, vm, &compute.VirtualMachinesClientBeginUpdateOptions{})
	if err != nil {
		return err
	}
	start := time.Now()
	for {
		log.Debug().Str("disk-name", diskName).Str("elapsed", time.Duration(time.Since(start)).String()).Msg("polling for disk detachment")
		_, err := poller.Poll(ctx)
		if err != nil {
			return err
		}

		if poller.Done() {
			break
		}
		time.Sleep(5 * time.Second)
	}

	_, err = poller.Result(ctx)
	return err
}

// deleteCreatedDisk deletes the given disk if it matches the created label
func (sc *snapshotCreator) deleteCreatedDisk(resourceGroup, diskName string) error {
	ctx := context.Background()

	diskSvc, err := sc.diskClient()
	if err != nil {
		return err
	}

	disk, err := diskSvc.Get(ctx, resourceGroup, diskName, &compute.DisksClientGetOptions{})
	if err != nil {
		return err
	}

	// only delete the volume if we created it, e.g., if we're scanning a snapshot
	if val, ok := disk.Tags[createdByLabel]; ok && *val == createdValue {
		poller, err := diskSvc.BeginDelete(ctx, resourceGroup, diskName, &compute.DisksClientBeginDeleteOptions{})
		if err != nil {
			return err
		}
		_, err = poller.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{
			Frequency: 5 * time.Second,
		})
		if err != nil {
			return err
		}
		log.Debug().Str("disk", diskName).Msg("deleted temporary disk created by cnspec")
	} else {
		log.Debug().Str("disk", diskName).Msg("skipping disk deletion, not created by cnspec")
	}

	return nil
}
