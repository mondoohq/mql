// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterDrives(t *testing.T) {
	t.Run("filter by serial number", func(t *testing.T) {
		opts := map[string]string{
			SerialNumberOption: "1234",
		}
		drives := []*diskDrive{
			{
				SerialNumber:    "1234",
				SCSILogicalUnit: 0,
				Index:           0,
				Name:            "a",
			},
			{
				SerialNumber:    "5678",
				SCSILogicalUnit: 1,
				Index:           1,
				Name:            "b",
			},
		}
		filtered, err := filterDiskDrives(drives, opts)
		require.NoError(t, err)
		expected := &diskDrive{
			SerialNumber:    "1234",
			SCSILogicalUnit: 0,
			Index:           0,
			Name:            "a",
		}
		require.Equal(t, expected, filtered)
	})

	// Win32_DiskDrive.SerialNumber values measured on Windows Server 2022.
	// Nitro (NVMe) appends the namespace ID and a trailing dot, Xen (SAS) does not.
	t.Run("filter by serial number on nitro and xen", func(t *testing.T) {
		nitroA := &diskDrive{SerialNumber: "vol0e216b22bfa34c476_00000001.", Index: 1, Name: "nitroA"}
		nitroB := &diskDrive{SerialNumber: "vol08a27a0b157097adb_00000001.", Index: 2, Name: "nitroB"}
		xen := &diskDrive{SerialNumber: "vol083a629b6325d8c5d", Index: 3, Name: "xen"}
		drives := []*diskDrive{nitroA, nitroB, xen}

		tests := []struct {
			name   string
			serial string
			want   *diskDrive
		}{
			{name: "nitro matches dashless volume id", serial: "vol0e216b22bfa34c476", want: nitroA},
			{name: "nitro picks the matching drive, not the first", serial: "vol08a27a0b157097adb", want: nitroB},
			{name: "xen exact match", serial: "vol083a629b6325d8c5d", want: xen},
			{name: "strict prefix of a volume id does not match", serial: "vol08a27a0b157097ad"},
			{name: "no match", serial: "vol065fe7667c527cbb2"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := filterDiskDrives(drives, map[string]string{SerialNumberOption: tc.serial})
				if tc.want == nil {
					require.EqualError(t, err, "no disk drive with matching serial number found")
					require.Nil(t, got)
					return
				}
				require.NoError(t, err)
				require.Same(t, tc.want, got)
			})
		}
	})

	t.Run("filter by LUN", func(t *testing.T) {
		opts := map[string]string{
			LunOption: "1",
		}
		drives := []*diskDrive{
			{
				SerialNumber:    "1234",
				SCSILogicalUnit: 0,
				Index:           0,
				Name:            "a",
			},
			{
				SerialNumber:    "5678",
				SCSILogicalUnit: 1,
				Index:           1,
				Name:            "b",
			},
		}
		filtered, err := filterDiskDrives(drives, opts)
		require.NoError(t, err)
		expected := &diskDrive{
			SerialNumber:    "5678",
			SCSILogicalUnit: 1,
			Index:           1,
			Name:            "b",
		}
		require.Equal(t, expected, filtered)
	})
	t.Run("filter by invalid LUN", func(t *testing.T) {
		opts := map[string]string{
			LunOption: "a",
		}
		drives := []*diskDrive{
			{
				SerialNumber:    "1234",
				SCSILogicalUnit: 0,
				Index:           0,
				Name:            "a",
			},
			{
				SerialNumber:    "5678",
				SCSILogicalUnit: 1,
				Index:           1,
				Name:            "b",
			},
		}
		_, err := filterDiskDrives(drives, opts)
		require.Error(t, err)
	})
}

func TestFilterPartitions(t *testing.T) {
	t.Run("find a partition (Basic type)", func(t *testing.T) {
		parts := []*diskPartition{
			{
				DriveLetter: "A",
				Size:        123,
				Type:        "Basic",
			},
			{
				Size: 123,
				Type: "Basic",
			},
		}
		part, err := filterPartitions(parts)
		require.NoError(t, err)
		expected := &diskPartition{
			DriveLetter: "A",
			Size:        123,
			Type:        "Basic",
		}
		require.Equal(t, expected, part)
	})

	t.Run("find a partition (IFS type)", func(t *testing.T) {
		parts := []*diskPartition{
			{
				DriveLetter: "A",
				Size:        123,
				Type:        "IFS",
			},
			{
				Size: 123,
				Type: "Basic",
			},
		}
		part, err := filterPartitions(parts)
		require.NoError(t, err)
		expected := &diskPartition{
			DriveLetter: "A",
			Size:        123,
			Type:        "IFS",
		}
		require.Equal(t, expected, part)
	})

	t.Run("no applicable partition", func(t *testing.T) {
		parts := []*diskPartition{
			{
				Size: 123,
				Type: "IFS",
			},
			{
				Size: 123,
				Type: "Basic",
			},
		}
		_, err := filterPartitions(parts)
		require.Error(t, err)
	})
}
