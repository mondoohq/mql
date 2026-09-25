// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadDebian13Topology reads real `lsblk --json --fs --output +TYPE,KNAME`
// output captured on a Debian 13 host (util-linux 2.41.5) carrying:
//   - loop0 (LUKS2) -> dm-0 crypt -> dm-2 lvm, ext4 mounted (LVM on LUKS)
//   - loop1 (plain PV) and loop2 (LUKS2) -> dm-1 crypt, both under one LV
//     dm-3 that spans the two, so lsblk prints dm-3 twice
//   - loop3 plain ext4 labeled mqlplain7q3k
//   - nvme0n1 -> nvme0n1p1 vfat /boot/efi, nvme0n1p2 ext4 /, nvme0n1p3 swap
func loadDebian13Topology(t *testing.T) *blockTopology {
	t.Helper()
	data, err := os.ReadFile("testdata/lsblk_debian13_luks_lvm.json")
	require.NoError(t, err)
	devices, err := parseBlockEntries(data)
	require.NoError(t, err)
	return buildBlockTopology(devices.Blockdevices)
}

func nodeKeys(nodes []*blockNode) []string {
	res := []string{}
	for _, n := range nodes {
		res = append(res, n.key)
	}
	return res
}

func TestBlockTopologyDecodesTypeAndKname(t *testing.T) {
	topo := loadDebian13Topology(t)

	lv := topo.byKname["dm-2"]
	require.NotNil(t, lv)
	assert.Equal(t, "mqltest--lsblk--7q3k--vg-enc", lv.dev.Name)
	assert.Equal(t, "lvm", lv.dev.Type)
	assert.Equal(t, "ext4", lv.dev.Fstype)
	assert.Equal(t, []any{"/mnt/mqltest-lsblk-7q3k-enc"}, lv.dev.Mountpoints)

	crypt := topo.byKname["dm-0"]
	require.NotNil(t, crypt)
	assert.Equal(t, "mqltest-lsblk-7q3k-crypt", crypt.dev.Name)
	assert.Equal(t, "crypt", crypt.dev.Type)

	assert.Equal(t, "loop", topo.byKname["loop0"].dev.Type)
	assert.Equal(t, "part", topo.byKname["nvme0n1p2"].dev.Type)
	assert.Equal(t, "disk", topo.byKname["nvme0n1"].dev.Type)
}

func TestBlockTopologyEdges(t *testing.T) {
	topo := loadDebian13Topology(t)

	// dm-3 is printed under loop1 and under dm-1 and must fold into a single
	// node with both parents.
	assert.Equal(t, []string{
		"loop0", "dm-0", "dm-2",
		"loop1", "dm-3",
		"loop2", "dm-1",
		"loop3",
		"nvme0n1", "nvme0n1p1", "nvme0n1p2", "nvme0n1p3",
	}, nodeKeys(topo.nodes))

	assert.Equal(t, []string{"loop1", "dm-1"}, nodeKeys(topo.byKname["dm-3"].parents))
	assert.Equal(t, []string{"dm-3"}, nodeKeys(topo.byKname["dm-1"].children))
	assert.Equal(t, []string{"dm-3"}, nodeKeys(topo.byKname["loop1"].children))

	// LVM on LUKS: lvm -> crypt -> loop
	assert.Equal(t, []string{"dm-0"}, nodeKeys(topo.byKname["dm-2"].parents))
	assert.Equal(t, []string{"loop0"}, nodeKeys(topo.byKname["dm-0"].parents))
	assert.Empty(t, topo.byKname["loop0"].parents)

	assert.Equal(t, []string{"nvme0n1p1", "nvme0n1p2", "nvme0n1p3"}, nodeKeys(topo.byKname["nvme0n1"].children))
	assert.Empty(t, topo.byKname["nvme0n1p2"].children)
}

func TestBlockTopologyFilesystemNodesListsSharedDeviceOnce(t *testing.T) {
	topo := loadDebian13Topology(t)
	// The partitioned disk is left out, the stacking members are kept, and dm-3
	// is reported once although lsblk printed it twice.
	assert.Equal(t, []string{
		"loop0", "dm-0", "dm-2",
		"loop1", "dm-3",
		"loop2", "dm-1",
		"loop3",
		"nvme0n1p1", "nvme0n1p2", "nvme0n1p3",
	}, nodeKeys(topo.filesystemNodes()))
}

func TestBlockTopologyKeyFallsBackToName(t *testing.T) {
	// Output without the KNAME column.
	devices, err := parseBlockEntries([]byte(`{"blockdevices":[
		{"name":"sdc","children":[{"name":"sdc1","fstype":"ext4","mountpoints":["/"]}]}
	]}`))
	require.NoError(t, err)
	topo := buildBlockTopology(devices.Blockdevices)
	require.NotNil(t, topo.byKname["sdc1"])
	assert.Equal(t, []string{"sdc"}, nodeKeys(topo.byKname["sdc1"].parents))
}

func TestBlockNodeEncryption(t *testing.T) {
	topo := loadDebian13Topology(t)

	tests := []struct {
		kname     string
		encrypted bool
	}{
		{"dm-2", true},       // LVM volume on a LUKS mapping
		{"dm-0", true},       // the LUKS mapping itself
		{"dm-1", true},       // second LUKS mapping
		{"loop0", false},     // the LUKS container holds ciphertext, not decrypted data
		{"dm-3", false},      // LV spanning an encrypted and a plain physical volume
		{"loop1", false},     // plain physical volume
		{"loop3", false},     // plain filesystem
		{"nvme0n1p2", false}, // root partition
		{"nvme0n1", false},   // whole disk
	}
	for _, test := range tests {
		t.Run(test.kname, func(t *testing.T) {
			encrypted, known := topo.byKname[test.kname].encryption()
			assert.True(t, known)
			assert.Equal(t, test.encrypted, encrypted)
		})
	}
}

func TestBlockNodeEncryptionUnknownType(t *testing.T) {
	// Without the TYPE column nothing can be said about any device.
	devices, err := parseBlockEntries([]byte(`{"blockdevices":[
		{"name":"sda","children":[{"name":"sda1","fstype":"ext4","mountpoints":["/"]}]}
	]}`))
	require.NoError(t, err)
	topo := buildBlockTopology(devices.Blockdevices)
	_, known := topo.byKname["sda1"].encryption()
	assert.False(t, known)

	// An LV over one encrypted PV and one PV of unknown type is unknown. An LV
	// over one plain PV and one of unknown type is known to be unencrypted.
	devices, err = parseBlockEntries([]byte(`{"blockdevices":[
		{"name":"a","kname":"a","type":"crypt","children":[{"name":"lv1","kname":"dm-5","type":"lvm"}]},
		{"name":"b","kname":"b","children":[{"name":"lv1","kname":"dm-5","type":"lvm"},{"name":"lv2","kname":"dm-6","type":"lvm"}]},
		{"name":"c","kname":"c","type":"disk","children":[{"name":"lv2","kname":"dm-6","type":"lvm"}]}
	]}`))
	require.NoError(t, err)
	topo = buildBlockTopology(devices.Blockdevices)
	_, known = topo.byKname["dm-5"].encryption()
	assert.False(t, known)

	encrypted, known := topo.byKname["dm-6"].encryption()
	assert.True(t, known)
	assert.False(t, encrypted)
}

func TestBlockTopologyResolve(t *testing.T) {
	topo := loadDebian13Topology(t)

	tests := []struct {
		name      string
		device    string
		mountPath string
		want      string // kname, empty for no match
	}{
		{"device-mapper path as mount prints it", "/dev/mapper/mqltest--lsblk--7q3k--vg-enc", "/mnt/mqltest-lsblk-7q3k-enc", "dm-2"},
		{"kernel name of a mapping", "/dev/dm-2", "", "dm-2"},
		{"LVM path with dashes in the names", "/dev/mqltest-lsblk-7q3k-vg/enc", "", "dm-2"},
		{"crypt mapping as cryptsetup names it", "/dev/mapper/mqltest-lsblk-7q3k-crypt", "", "dm-0"},
		{"partition", "/dev/nvme0n1p2", "/", "nvme0n1p2"},
		{"loop device", "/dev/loop3", "", "loop3"},
		{"by-uuid link", "/dev/disk/by-uuid/38470e21-9308-4475-8872-2e3efaeac53e", "", "loop3"},
		{"by-label link", "/dev/disk/by-label/mqlplain7q3k", "", "loop3"},
		{"unknown device falls back to the mount path", "/dev/root", "/", "nvme0n1p2"},
		{"unknown device and unknown mount path", "/dev/root", "/srv", ""},
		{"unknown device without mount path", "/dev/sdz9", "", ""},
		{"unknown uuid", "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000", "", ""},
		{"tmpfs", "tmpfs", "/tmp", ""},
		{"overlay", "overlay", "/", ""},
		{"proc", "proc", "/proc", ""},
		{"nfs export", "server:/export", "/mnt/nfs", ""},
		{"zfs dataset", "storage", "/storage", ""},
		{"bare /dev", "/dev/", "/", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := topo.resolve(test.device, test.mountPath)
			if test.want == "" {
				assert.Nil(t, node)
				return
			}
			require.NotNil(t, node)
			assert.Equal(t, test.want, node.key)
		})
	}
}

func TestBlockTopologyResolveAmbiguous(t *testing.T) {
	// sda, sdb and sdd are members of one btrfs volume and share its UUID and
	// label, so neither link names a single device. The mount path settles
	// it, because lsblk reports the mount on one member only.
	devices, err := parseBlockEntries([]byte(`{"blockdevices":[
		{"name":"sda","kname":"sda","type":"disk","fstype":"btrfs","label":"storage01","uuid":"6060df9a-7e53-439c-9189-ba9657161fd4","mountpoints":["/data"]},
		{"name":"sdb","kname":"sdb","type":"disk","fstype":"btrfs","label":"storage01","uuid":"6060df9a-7e53-439c-9189-ba9657161fd4","mountpoints":[null]},
		{"name":"sdd","kname":"sdd","type":"disk","fstype":"btrfs","label":"storage01","uuid":"6060df9a-7e53-439c-9189-ba9657161fd4","mountpoints":[null]}
	]}`))
	require.NoError(t, err)
	topo := buildBlockTopology(devices.Blockdevices)

	assert.Nil(t, topo.resolve("/dev/disk/by-uuid/6060df9a-7e53-439c-9189-ba9657161fd4", ""))
	assert.Nil(t, topo.resolve("/dev/disk/by-label/storage01", ""))

	node := topo.resolve("/dev/disk/by-uuid/6060df9a-7e53-439c-9189-ba9657161fd4", "/data")
	require.NotNil(t, node)
	assert.Equal(t, "sda", node.key)
}

func TestBlockTopologyResolveNil(t *testing.T) {
	var topo *blockTopology
	assert.Nil(t, topo.resolve("/dev/sda1", "/"))
}

func TestUnescapeUdev(t *testing.T) {
	assert.Equal(t, "My Disk", unescapeUdev(`My\x20Disk`))
	assert.Equal(t, "a/b", unescapeUdev(`a\x2fb`))
	assert.Equal(t, "plain", unescapeUdev("plain"))
	// malformed or truncated escapes are kept as written
	assert.Equal(t, `bad\xZZ`, unescapeUdev(`bad\xZZ`))
	assert.Equal(t, `end\x2`, unescapeUdev(`end\x2`))
}

func TestDmEscape(t *testing.T) {
	assert.Equal(t, "my--vg", dmEscape("my-vg"))
	assert.Equal(t, "root", dmEscape("root"))
}
