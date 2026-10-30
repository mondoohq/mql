// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/id/azcompute"
)

func (c *AzureSnapshotConnection) setupDiskAndMount(target scanTarget, lun int) (mountedDiskInfo, assetInfo, error) {
	mi, ai, err := c.setupDisk(target)
	if err != nil {
		return mountedDiskInfo{}, assetInfo{}, err
	}
	err = c.snapshotCreator.attachDisk(c.instanceInfo, mi.diskName, mi.diskId, lun)
	if err != nil {
		return mountedDiskInfo{}, assetInfo{}, err
	}

	return mi, ai, nil
}

func (c *AzureSnapshotConnection) setupDisk(target scanTarget) (mountedDiskInfo, assetInfo, error) {
	mi := mountedDiskInfo{}
	ai := assetInfo{}
	h := sha256.New()
	now := time.Now()
	// ensure no name collisions if performing multiple snapshot scans at once
	h.Write([]byte(target.Target))
	h.Write([]byte(target.TargetType))
	h.Write([]byte(target.ResourceGroup))
	h.Write([]byte(target.SubscriptionId))
	h.Write([]byte(now.Format("2006-01-02t15-04-05z00-00")))

	diskHash := fmt.Sprintf("%x", h.Sum(nil))
	diskName := fmt.Sprintf("mondoo-snapshot-%s-%s", diskHash[:8], now.Format("2006-01-02t15-04-05z00-00"))
	switch target.TargetType {
	case InstanceTargetType:
		log.Debug().Str("instance", target.Target).Msg("azure snapshot> targeting instance")
		instanceInfo, err := c.snapshotCreator.instanceInfo(target.ResourceGroup, target.Target)
		if err != nil {
			return mountedDiskInfo{}, assetInfo{}, err
		}
		if instanceInfo.bootDiskId == "" {
			return mountedDiskInfo{}, assetInfo{}, fmt.Errorf("could not find boot disk for instance %s", target.Target)
		}

		log.Debug().Str("boot disk", instanceInfo.bootDiskId).Msg("found boot disk for instance, cloning")
		disk, err := c.snapshotCreator.cloneDisk(instanceInfo.bootDiskId, c.instanceInfo.resourceGroup, diskName, c.instanceInfo.location, c.instanceInfo.vm.Zones)
		if err != nil {
			log.Error().Err(err).Msg("could not complete disk cloning")
			return mountedDiskInfo{}, assetInfo{}, errors.Wrap(err, "could not complete disk cloning")
		}
		log.Debug().Str("disk", *disk.ID).Msg("cloned disk from instance boot disk")
		mi.diskId = *disk.ID
		mi.diskName = *disk.Name
		ai.assetName = instanceInfo.instanceName
		ai.platformId = azcompute.MondooAzureInstanceID(*instanceInfo.vm.ID)
	case SnapshotTargetType:
		log.Debug().Str("snapshot", target.Target).Msg("azure snapshot> targeting snapshot")
		snapshotInfo, err := c.snapshotCreator.snapshotInfo(target.ResourceGroup, target.Target)
		if err != nil {
			return mountedDiskInfo{}, assetInfo{}, err
		}

		disk, err := c.snapshotCreator.createSnapshotDisk(snapshotInfo.snapshotId, c.instanceInfo.resourceGroup, diskName, c.instanceInfo.location, c.instanceInfo.vm.Zones)
		if err != nil {
			log.Error().Err(err).Msg("could not complete snapshot disk creation")
			return mountedDiskInfo{}, assetInfo{}, errors.Wrap(err, "could not create disk from snapshot")
		}
		log.Debug().Str("disk", *disk.ID).Msg("created disk from snapshot")
		mi.diskId = *disk.ID
		mi.diskName = *disk.Name
		ai.assetName = target.Target
		ai.platformId = SnapshotPlatformMrn(snapshotInfo.snapshotId)
	case DiskTargetType:
		log.Debug().Str("disk", target.Target).Msg("azur snapshot> targeting disk")
		diskInfo, err := c.snapshotCreator.diskInfo(target.ResourceGroup, target.Target)
		if err != nil {
			return mountedDiskInfo{}, assetInfo{}, err
		}

		disk, err := c.snapshotCreator.cloneDisk(diskInfo.diskId, c.instanceInfo.resourceGroup, diskName, c.instanceInfo.location, c.instanceInfo.vm.Zones)
		if err != nil {
			log.Error().Err(err).Msg("could not complete disk cloning")
			return mountedDiskInfo{}, assetInfo{}, errors.Wrap(err, "could not complete disk cloning")
		}
		log.Debug().Str("disk", *disk.ID).Msg("cloned disk from target disk")
		mi.diskId = *disk.ID
		mi.diskName = *disk.Name
		ai.assetName = diskInfo.diskName
		ai.platformId = DiskPlatformMrn(diskInfo.diskId)
	default:
		return mountedDiskInfo{}, assetInfo{}, errors.New("invalid target type")
	}

	return mi, ai, nil
}
