// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package device

import (
	"go.mondoo.com/mql/providers/os/connection/snapshot"
)

type DeviceManager interface {
	// Name returns the name of the device manager
	Name() string
	// IdentifyMountTargets returns a list of partitions that match the given options and can be mounted
	IdentifyMountTargets(opts map[string]string) ([]*snapshot.Partition, error)
	// Mounts partitions and returns the directories they were mounted to
	Mount(partitions []*snapshot.Partition) ([]*snapshot.MountedPartition, error)
	// UnmountAndClose unmounts the partitions from the specified dirs and closes the device manager
	UnmountAndClose()
}
