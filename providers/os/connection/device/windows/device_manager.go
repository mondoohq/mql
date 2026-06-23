// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"errors"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/snapshot"
)

const (
	LunOption          = "lun"
	LunsOption         = "luns"
	SerialNumberOption = "serial-number"
)

type WindowsDeviceManager struct {
	cmdRunner *snapshot.LocalCommandRunner
	opts      map[string]string
	// indicates if the disk we've targeted has been set to online. we use this to know if we need to put it back offline once we're done
	diskSetToOnline bool
	// indicates if the disk we've targeted has been set to readonly=false. we use this to know if we need to put it back to readonly once we're done
	diskSetToReadonly bool
	// if we've set the disk online, we need to know the index to set it back offline
	diskIndex int
}

func NewWindowsDeviceManager(shell []string, opts map[string]string) (*WindowsDeviceManager, error) {
	if err := validateOpts(opts); err != nil {
		return nil, err
	}
	return &WindowsDeviceManager{
		cmdRunner: &snapshot.LocalCommandRunner{Shell: shell},
		opts:      opts,
	}, nil
}

func (d *WindowsDeviceManager) Name() string {
	return "windows"
}

func (d *WindowsDeviceManager) IdentifyMountTargets(opts map[string]string) ([]*snapshot.Partition, error) {
	log.Debug().Msg("device connection> identifying mount targets")
	diskDrives, err := d.IdentifyDiskDrives()
	if err != nil {
		return nil, err
	}

	targetDrive, err := filterDiskDrives(diskDrives, opts)
	if err != nil {
		return nil, err
	}

	diskStatus, err := d.identifyDiskStatus(targetDrive.Index)
	if err != nil {
		return nil, err
	}
	if diskStatus.Readonly {
		err = d.setDiskReadonlyState(targetDrive.Index, false)
		if err != nil {
			return nil, err
		}
		d.diskSetToReadonly = true
		d.diskIndex = targetDrive.Index
	}
	if diskStatus.Offline {
		err = d.setDiskOnlineState(targetDrive.Index, true)
		if err != nil {
			return nil, err
		}
		d.diskSetToOnline = true
		d.diskIndex = targetDrive.Index
	}

	partitions, err := d.identifyPartitions(targetDrive.Index)
	if err != nil {
		return nil, err
	}
	partition, err := filterPartitions(partitions)
	if err != nil {
		return nil, err
	}
	partitionInfo := &snapshot.Partition{
		Name:   partition.DriveLetter,
		FsType: "Windows",
	}
	return []*snapshot.Partition{partitionInfo}, nil
}

// validates the options provided to the device manager
func validateOpts(opts map[string]string) error {
	lunPresent := opts[LunOption] != "" || opts[LunsOption] != ""
	serialNumberPresent := opts[SerialNumberOption] != ""

	if lunPresent && serialNumberPresent {
		return errors.New("lun and serial-number are mutually exclusive options")
	}

	if !lunPresent && !serialNumberPresent {
		return errors.New("either lun or serial-number must be provided")
	}

	return nil
}

func (d *WindowsDeviceManager) Mount(partitions []*snapshot.Partition) ([]*snapshot.MountedPartition, error) {
	res := []*snapshot.MountedPartition{}
	for _, partition := range partitions {
		name := partition.Name
		if !strings.HasSuffix(name, ":") {
			name += ":"
		}
		mp := &snapshot.MountedPartition{
			Partition:    partition,
			MountPoint:   name,
			MountOptions: []string{}, // Windows does not use mount options like Linux
		}
		res = append(res, mp)
	}
	return res, nil
}

func (d *WindowsDeviceManager) UnmountAndClose() {
	log.Debug().Msg("closing windows device manager")
	if d.diskSetToOnline {
		err := d.setDiskOnlineState(d.diskIndex, false)
		if err != nil {
			log.Debug().Err(err).Msg("could not set disk offline")
		}
	}
	if d.diskSetToReadonly {
		err := d.setDiskReadonlyState(d.diskIndex, true)
		if err != nil {
			log.Debug().Err(err).Msg("could not set disk readonly")
		}
	}
}
