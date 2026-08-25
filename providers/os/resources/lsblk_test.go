// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBlockEntries(t *testing.T) {
	data := `{"blockdevices": [
			 {
					"name": "loop0",
					"fstype": "squashfs",
					"fsver": "4.0",
					"label": null,
					"uuid": null,
					"fsavail": "0",
					"fsuse%": "100%",
					"mountpoints": [
							"/var/lib/snapd/snap/core/10577"
					]
			 },{
					"name": "sda",
					"fstype": "btrfs",
					"fsver": null,
					"label": "storage01",
					"uuid": "6060df9a-7e53-439c-9189-ba9657161fd4",
					"fsavail": "764.8G",
					"fsuse%": "80%",
					"mountpoints": [
							"/data"
					]
			 },{
					"name": "sdb",
					"fstype": "btrfs",
					"fsver": null,
					"label": "storage01",
					"uuid": "6060df9a-7e53-439c-9189-ba9657161fd4",
					"fsavail": null,
					"fsuse%": null,
					"mountpoints": [
							null
					]
			 },{
					"name": "sdc",
					"fstype": null,
					"fsver": null,
					"label": null,
					"uuid": null,
					"fsavail": null,
					"fsuse%": null,
					"mountpoints": [
							null
					],
					"children": [
						 {
								"name": "sdc1",
								"fstype": "vfat",
								"fsver": "FAT32",
								"label": null,
								"uuid": "0EC7-F4C1",
								"fsavail": "193.5M",
								"fsuse%": "62%",
								"mountpoints": [
										"/boot"
								]
						 },{
								"name": "sdc2",
								"fstype": "ext4",
								"fsver": "1.0",
								"label": null,
								"uuid": "6c44ec5a-4727-47d4-b485-81cff72b207e",
								"fsavail": "80.2G",
								"fsuse%": "77%",
								"mountpoints": [
										"/"
								]
						 }
					]
			 },{
					"name": "sdd",
					"fstype": "btrfs",
					"fsver": null,
					"label": "storage01",
					"uuid": "6060df9a-7e53-439c-9189-ba9657161fd4",
					"fsavail": null,
					"fsuse%": null,
					"mountpoints": [
							null
					]
			 }
		]
 }`
	devices, err := parseBlockEntries([]byte(data))
	assert.Nil(t, err)
	assert.Equal(t, 5, len(devices.Blockdevices))
	assert.Equal(t, []blockdevice{{
		Name:        "loop0",
		Fstype:      "squashfs",
		Label:       "",
		Uuid:        "",
		Mountpoints: []any{"/var/lib/snapd/snap/core/10577"},
	}, {
		Name:        "sda",
		Fstype:      "btrfs",
		Label:       "storage01",
		Uuid:        "6060df9a-7e53-439c-9189-ba9657161fd4",
		Mountpoints: []any{"/data"},
	}, {
		Name:        "sdb",
		Fstype:      "btrfs",
		Label:       "storage01",
		Uuid:        "6060df9a-7e53-439c-9189-ba9657161fd4",
		Mountpoints: nil,
	}, {
		Name:        "sdc",
		Fstype:      "",
		Label:       "",
		Uuid:        "",
		Mountpoints: nil,
		Children: []blockdevice{{
			Name:        "sdc1",
			Fstype:      "vfat",
			Label:       "",
			Uuid:        "0EC7-F4C1",
			Mountpoints: []any{"/boot"},
		}, {
			Name:        "sdc2",
			Fstype:      "ext4",
			Label:       "",
			Uuid:        "6c44ec5a-4727-47d4-b485-81cff72b207e",
			Mountpoints: []any{"/"},
		}},
	}, {
		Name:        "sdd",
		Fstype:      "btrfs",
		Label:       "storage01",
		Uuid:        "6060df9a-7e53-439c-9189-ba9657161fd4",
		Mountpoints: nil,
	}}, devices.Blockdevices)

	data = `{
		"blockdevices": [
			 {"name": "xvda", "fstype": null, "label": null, "uuid": null, "mountpoint": null,
					"children": [
						 {"name": "xvda1", "fstype": "xfs", "label": "/", "uuid": "e6c06bf4-70a3-4524-84fa-35484afc0d19", "mountpoint": "/"}
					]
			 }
		]
 }`
	devices, err = parseBlockEntries([]byte(data))
	assert.Nil(t, err)
	assert.Equal(t, len(devices.Blockdevices), 1)
	assert.Equal(t, devices.Blockdevices, []blockdevice{{
		Name:       "xvda",
		Mountpoint: "",
		Children: []blockdevice{{
			Name:        "xvda1",
			Fstype:      "xfs",
			Label:       "/",
			Uuid:        "e6c06bf4-70a3-4524-84fa-35484afc0d19",
			Mountpoint:  "/",
			Mountpoints: []any{"/"},
		}},
	}})
}

func TestParseBlockEntriesEmpty(t *testing.T) {
	devices, err := parseBlockEntries([]byte(`{"blockdevices": []}`))
	assert.Nil(t, err)
	assert.Empty(t, devices.Blockdevices)
	assert.Empty(t, filesystemDevices(devices.Blockdevices))
}

func TestFilesystemDevices(t *testing.T) {
	tests := []struct {
		name string
		data string
		// expected device names, in the order they are emitted
		expected []string
	}{
		{
			// The root filesystem sits directly on an unpartitioned disk, so
			// lsblk reports a single device with no children at all. Alpine
			// 3.23.5 on EC2, util-linux lsblk 2.41.4.
			name:     "filesystem on the whole disk",
			data:     `{"blockdevices":[{"name":"nvme0n1","fstype":null,"fsavail":"17.1G","mountpoints":["/"]}]}`,
			expected: []string{"nvme0n1"},
		},
		{
			// The disk only carries a partition table, so it is skipped in
			// favor of the partition that holds the filesystem.
			name: "filesystem on a partition",
			data: `{"blockdevices":[
				{"name":"nvme0n1","fstype":null,"mountpoints":[null],"children":[
					{"name":"nvme0n1p1","fstype":"ext4","uuid":"6c44ec5a-4727-47d4-b485-81cff72b207e","mountpoints":["/"]}
				]}
			]}`,
			expected: []string{"nvme0n1p1"},
		},
		{
			// disk -> partition -> crypt -> lvm. Every stacking member reports
			// an fstype of its own, and the leaf volumes hold the filesystems.
			name: "stacked luks and lvm volumes",
			data: `{"blockdevices":[
				{"name":"sda","fstype":null,"mountpoints":[null],"children":[
					{"name":"sda1","fstype":"vfat","mountpoints":["/boot"]},
					{"name":"sda2","fstype":"crypto_LUKS","mountpoints":[null],"children":[
						{"name":"cryptroot","fstype":"LVM2_member","mountpoints":[null],"children":[
							{"name":"vg-root","fstype":"ext4","mountpoints":["/"]},
							{"name":"vg-swap","fstype":"swap","mountpoints":["[SWAP]"]}
						]}
					]}
				]}
			]}`,
			expected: []string{"sda1", "sda2", "cryptroot", "vg-root", "vg-swap"},
		},
		{
			name:     "no block devices",
			data:     `{"blockdevices":[]}`,
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			devices, err := parseBlockEntries([]byte(test.data))
			assert.Nil(t, err)

			names := []string{}
			for _, d := range filesystemDevices(devices.Blockdevices) {
				names = append(names, d.Name)
			}
			assert.Equal(t, test.expected, names)
		})
	}
}

func TestFilesystemDevicesWholeDiskMountpoint(t *testing.T) {
	data := `{"blockdevices":[{"name":"nvme0n1","fstype":null,"fsavail":"17.1G","mountpoints":["/"]}]}`

	devices, err := parseBlockEntries([]byte(data))
	assert.Nil(t, err)

	entries := filesystemDevices(devices.Blockdevices)
	assert.Equal(t, 1, len(entries))
	assert.Equal(t, "nvme0n1", entries[0].Name)
	assert.Equal(t, []any{"/"}, entries[0].Mountpoints)
}

func TestFilesystemDevicesMixedTopLevel(t *testing.T) {
	// Unpartitioned data disks alongside a partitioned system disk: the data
	// disks are emitted, the partition table holder is not.
	data := `{"blockdevices":[
		{"name":"loop0","fstype":"squashfs","mountpoints":["/var/lib/snapd/snap/core/10577"]},
		{"name":"sda","fstype":"btrfs","label":"storage01","mountpoints":["/data"]},
		{"name":"sdb","fstype":"btrfs","label":"storage01","mountpoints":[null]},
		{"name":"sdc","fstype":null,"mountpoints":[null],"children":[
			{"name":"sdc1","fstype":"vfat","mountpoints":["/boot"]},
			{"name":"sdc2","fstype":"ext4","mountpoints":["/"]}
		]}
	]}`

	devices, err := parseBlockEntries([]byte(data))
	assert.Nil(t, err)

	names := []string{}
	for _, d := range filesystemDevices(devices.Blockdevices) {
		names = append(names, d.Name)
	}
	assert.Equal(t, []string{"loop0", "sda", "sdb", "sdc1", "sdc2"}, names)
}

func TestNormalizeMountpointsNested(t *testing.T) {
	// The single-mountpoint form has to be reconciled at every level of the
	// tree, not just for the direct children of a disk.
	data := `{"blockdevices":[
		{"name":"sda","fstype":null,"mountpoint":null,"children":[
			{"name":"sda1","fstype":"LVM2_member","mountpoint":null,"children":[
				{"name":"vg-root","fstype":"xfs","mountpoint":"/"}
			]}
		]}
	]}`

	devices, err := parseBlockEntries([]byte(data))
	assert.Nil(t, err)
	assert.Empty(t, devices.Blockdevices[0].Mountpoints)
	assert.Empty(t, devices.Blockdevices[0].Children[0].Mountpoints)
	assert.Equal(t, []any{"/"}, devices.Blockdevices[0].Children[0].Children[0].Mountpoints)
}
