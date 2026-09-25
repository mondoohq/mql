// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package linux

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/connection/snapshot"
	"go.mondoo.com/mql/providers/os/resources/fstab"
	"go.uber.org/mock/gomock"
)

type deviceManagerTestFixture struct {
	dmgr          *LinuxDeviceManager
	volumeMounter *snapshot.MockVolumeMounter

	mockCtrl *gomock.Controller
}

func newFixture(t *testing.T) *deviceManagerTestFixture {
	ctrl := gomock.NewController(t)
	volumeMounter := snapshot.NewMockVolumeMounter(ctrl)

	return &deviceManagerTestFixture{
		dmgr: &LinuxDeviceManager{
			volumeMounter: volumeMounter,
			opts:          make(map[string]string),
		},
		volumeMounter: volumeMounter,

		mockCtrl: ctrl,
	}
}

func TestMountWithFstab(t *testing.T) {
	f := newFixture(t)
	t.Run("happy path", func(t *testing.T) {
		partitions := []*snapshot.Partition{
			{
				Name:   "/dev/sdf1",
				FsType: "ext4",
				Uuid:   "sdf1-uuid",
			},
			{
				Name:     "/dev/sdf3",
				FsType:   "fat32",
				PartUuid: "sdf3-uuid",
			},
			{
				Name:   "/dev/sdg1",
				FsType: "ext4",
				Label:  "data-label",
			},
		}
		entries := []fstab.Entry{
			{
				Device:     "UUID=sdf1-uuid",
				Mountpoint: "/",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
			{
				Device:     "PARTUUID=sdf3-uuid",
				Mountpoint: "/boot/efi",
				Fstype:     "fat32",
				Options:    []string{"defaults"},
			},
			{
				Device:     "LABEL=data-label",
				Mountpoint: "/data",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
		}

		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[0]}).
			Return(&snapshot.MountedPartition{Partition: partitions[0], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[1], MountDir: "/tmp/scandir/boot/efi"}).
			Return(&snapshot.MountedPartition{Partition: partitions[1], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir/boot/efi"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[2], MountDir: "/tmp/scandir/data"}).
			Return(&snapshot.MountedPartition{Partition: partitions[2], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir/data"}, nil).
			Times(1)

		result, err := f.dmgr.mountWithFstab(partitions, entries)
		assert.NoError(t, err)
		assert.Len(t, result, 3)

		assert.Equal(t, "/dev/sdf1", result[0].Partition.Name)
		assert.Equal(t, "/tmp/scandir", result[0].MountPoint)

		assert.Equal(t, "/dev/sdg1", result[1].Partition.Name)
		assert.Equal(t, "/tmp/scandir/data", result[1].MountPoint)

		assert.Equal(t, "/dev/sdf3", result[2].Partition.Name)
		assert.Equal(t, "/tmp/scandir/boot/efi", result[2].MountPoint)
	})

	t.Run("double mounted", func(t *testing.T) {
		partitions := []*snapshot.Partition{
			{
				Name:   "/dev/sdf1",
				FsType: "btrfs",
				Uuid:   "sdf1-uuid",
			},
			{
				Name:     "/dev/sdf3",
				FsType:   "fat32",
				PartUuid: "sdf3-uuid",
			},
			{
				Name:   "/dev/sdg1",
				FsType: "ext4",
				Label:  "data-label",
			},
		}
		entries := []fstab.Entry{
			{
				Device:     "UUID=sdf1-uuid",
				Mountpoint: "/",
				Fstype:     "btrfs",
				Options:    []string{"defaults", "subvolume=root"},
			},
			{
				Device:     "UUID=sdf1-uuid",
				Mountpoint: "/home",
				Fstype:     "btrfs",
				Options:    []string{"defaults", "subvolume=home"},
			},
			{
				Device:     "PARTUUID=sdf3-uuid",
				Mountpoint: "/boot/efi",
				Fstype:     "fat32",
				Options:    []string{"defaults"},
			},
			{
				Device:     "LABEL=data-label",
				Mountpoint: "/data",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
		}

		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults", "subvolume=root"}, Partition: partitions[0]}).
			Return(&snapshot.MountedPartition{Partition: partitions[0], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults", "subvolume=home"}, Partition: partitions[0], MountDir: "/tmp/scandir/home"}).
			Return(&snapshot.MountedPartition{Partition: partitions[0], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir/home"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[2], MountDir: "/tmp/scandir/data"}).
			Return(&snapshot.MountedPartition{Partition: partitions[2], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir/data"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[1], MountDir: "/tmp/scandir/boot/efi"}).
			Return(&snapshot.MountedPartition{Partition: partitions[1], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir/boot/efi"}, nil).
			Times(1)

		result, err := f.dmgr.mountWithFstab(partitions, entries)
		assert.NoError(t, err)
		assert.Len(t, result, 4)

		assert.Equal(t, "/dev/sdf1", result[0].Partition.Name)
		assert.Equal(t, "/tmp/scandir", result[0].MountPoint)

		assert.Equal(t, "/dev/sdf1", result[1].Partition.Name)
		assert.Equal(t, "/tmp/scandir/home", result[1].MountPoint)

		assert.Equal(t, "/dev/sdg1", result[2].Partition.Name)
		assert.Equal(t, "/tmp/scandir/data", result[2].MountPoint)

		assert.Equal(t, "/dev/sdf3", result[3].Partition.Name)
		assert.Equal(t, "/tmp/scandir/boot/efi", result[3].MountPoint)
	})

	t.Run("no entries matched", func(t *testing.T) {
		partitions := []*snapshot.Partition{
			{
				Name:   "/dev/sdf1",
				FsType: "ext4",
				Uuid:   "sdf1-uuid",
			},
			{
				Name:     "/dev/sdf3",
				FsType:   "fat32",
				PartUuid: "sdf3-uuid",
			},
			{
				Name:   "/dev/sdg1",
				FsType: "ext4",
				Label:  "data-label",
			},
		}
		entries := []fstab.Entry{
			{
				Device:     "UUID=sdf1-wrong-uuid",
				Mountpoint: "/",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
			{
				Device:     "PARTUUID=sdf3-wrong-uuid",
				Mountpoint: "/boot/efi",
				Fstype:     "fat32",
				Options:    []string{"defaults"},
			},
			{
				Device:     "LABEL=data-wrong-label",
				Mountpoint: "/data",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
		}

		result, err := f.dmgr.mountWithFstab(partitions, entries)
		assert.NoError(t, err)
		assert.Len(t, result, 0)
	})

	t.Run("root not found", func(t *testing.T) {
		partitions := []*snapshot.Partition{
			{
				Name:   "/dev/sdf1",
				FsType: "ext4",
				Uuid:   "sdf1-uuid",
			},
			{
				Name:     "/dev/sdf3",
				FsType:   "fat32",
				PartUuid: "sdf3-uuid",
			},
			{
				Name:   "/dev/sdg1",
				FsType: "ext4",
				Label:  "data-label",
			},
		}
		entries := []fstab.Entry{
			{
				Device:     "UUID=sdf1-wrong-uuid",
				Mountpoint: "/",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
			{
				Device:     "PARTUUID=sdf3-uuid",
				Mountpoint: "/boot/efi",
				Fstype:     "fat32",
				Options:    []string{"defaults"},
			},
			{
				Device:     "LABEL=data-label",
				Mountpoint: "/data",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
		}

		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[2]}).
			Return(&snapshot.MountedPartition{Partition: partitions[2], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir1"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[1]}).
			Return(&snapshot.MountedPartition{Partition: partitions[1], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir2"}, nil).
			Times(1)

		result, err := f.dmgr.mountWithFstab(partitions, entries)
		assert.NoError(t, err)
		assert.Len(t, result, 2)

		assert.Equal(t, "/dev/sdg1", result[0].Partition.Name)
		assert.Equal(t, "/tmp/scandir1", result[0].MountPoint)

		assert.Equal(t, "/dev/sdf3", result[1].Partition.Name)
		assert.Equal(t, "/tmp/scandir2", result[1].MountPoint)
	})

	t.Run("one not found", func(t *testing.T) {
		partitions := []*snapshot.Partition{
			{
				Name:   "/dev/sdf1",
				FsType: "ext4",
				Uuid:   "sdf1-uuid",
			},
			{
				Name:     "/dev/sdf3",
				FsType:   "fat32",
				PartUuid: "sdf3-uuid",
			},
			{
				Name:   "/dev/sdg1",
				FsType: "ext4",
				Label:  "data-label",
			},
		}
		entries := []fstab.Entry{
			{
				Device:     "UUID=sdf1-uuid",
				Mountpoint: "/",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
			{
				Device:     "PARTUUID=sdf3-uuid",
				Mountpoint: "/boot/efi",
				Fstype:     "fat32",
				Options:    []string{"defaults"},
			},
			{
				Device:     "LABEL=data-wrong-label",
				Mountpoint: "/data",
				Fstype:     "ext4",
				Options:    []string{"defaults"},
			},
		}

		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[0]}).
			Return(&snapshot.MountedPartition{Partition: partitions[0], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir"}, nil).
			Times(1)
		f.volumeMounter.
			EXPECT().
			Mount(&snapshot.MountPartitionInput{MountOptions: []string{"defaults"}, Partition: partitions[1], MountDir: "/tmp/scandir/boot/efi"}).
			Return(&snapshot.MountedPartition{Partition: partitions[1], MountOptions: []string{"defaults"}, MountPoint: "/tmp/scandir/boot/efi"}, nil).
			Times(1)

		result, err := f.dmgr.mountWithFstab(partitions, entries)
		assert.NoError(t, err)
		assert.Len(t, result, 2)

		assert.Equal(t, "/dev/sdf1", result[0].Partition.Name)
		assert.Equal(t, "/tmp/scandir", result[0].MountPoint)

		assert.Equal(t, "/dev/sdf3", result[1].Partition.Name)
		assert.Equal(t, "/tmp/scandir/boot/efi", result[1].MountPoint)
	})
}
