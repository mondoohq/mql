// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The testdata is real `lsblk --pairs --output
// NAME,KNAME,PKNAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT` output (with and
// without --paths) captured on RHEL 7.9 (util-linux 2.23.2, no --json),
// carrying:
//   - loop1 + nvme1n1p2 + nvme2n1p2 -> md0 (RAID1), printed under each member
//   - loop2 + loop3 -> md127 (RAID0) ext4 mounted at /mnt/md
//   - loop4 LUKS1, nvme3n1p1 LUKS2 -> dm-9 crypt ext4 mounted at /mnt/crypt
//   - an LVM thin pool dm-6 spanning dm-5 and dm-4, with dm-7 and dm-8 on it
//   - an LVM snapshot dm-3 on dm-1 and dm-2
func loadRhel7PairsTopology(t *testing.T) *blockTopology {
	t.Helper()
	data, err := os.ReadFile("testdata/lsblk_rhel7_pairs.txt")
	require.NoError(t, err)
	devices, err := parseBlockEntries(data)
	require.NoError(t, err)
	return buildBlockTopology(devices.Blockdevices)
}

func TestParseBlockPairsRebuildsTree(t *testing.T) {
	topo := loadRhel7PairsTopology(t)

	// every device once, in the order lsblk first prints it
	assert.Equal(t, []string{
		"zd0", "loop0", "loop1", "md0", "loop2", "md127", "loop3", "loop4",
		"nvme0n1", "nvme0n1p1", "nvme0n1p2",
		"nvme1n1", "nvme1n1p1", "dm-1", "dm-0", "dm-3", "dm-2", "dm-5", "dm-6", "dm-7", "dm-8", "nvme1n1p2",
		"nvme2n1", "nvme2n1p1", "dm-4", "nvme2n1p2",
		"nvme3n1", "nvme3n1p1", "dm-9", "nvme3n1p2",
	}, nodeKeys(topo.nodes))

	assert.Equal(t, []string{"loop1", "nvme1n1p2", "nvme2n1p2"}, nodeKeys(topo.byKname["md0"].parents))
	assert.Equal(t, []string{"loop2", "loop3"}, nodeKeys(topo.byKname["md127"].parents))
	assert.Equal(t, []string{"dm-5", "dm-4"}, nodeKeys(topo.byKname["dm-6"].parents))
	assert.Equal(t, []string{"dm-7", "dm-8"}, nodeKeys(topo.byKname["dm-6"].children))
	assert.Equal(t, []string{"dm-1", "dm-2"}, nodeKeys(topo.byKname["dm-3"].parents))
	assert.Equal(t, []string{"dm-1", "dm-2", "dm-5"}, nodeKeys(topo.byKname["nvme1n1p1"].children))
	assert.Empty(t, topo.byKname["nvme1n1"].parents)
}

func TestParseBlockPairsDeviceFields(t *testing.T) {
	topo := loadRhel7PairsTopology(t)

	crypt := topo.byKname["dm-9"]
	require.NotNil(t, crypt)
	assert.Equal(t, "g05crypt", crypt.dev.Name)
	assert.Equal(t, "crypt", crypt.dev.Type)
	assert.Equal(t, "ext4", crypt.dev.Fstype)
	assert.Equal(t, "cryptfs", crypt.dev.Label)
	assert.Equal(t, "3fcaf54e-9d32-45b6-b598-2cbfeee80344", crypt.dev.Uuid)
	assert.Equal(t, []any{"/mnt/crypt"}, crypt.dev.Mountpoints)

	// an empty MOUNTPOINT is no mount point, not ""
	assert.Empty(t, topo.byKname["nvme3n1p1"].dev.Mountpoints)
	assert.Empty(t, topo.byKname["nvme3n1p1"].dev.Label)

	encrypted, known := crypt.encryption()
	assert.True(t, known)
	assert.True(t, encrypted)
	encrypted, known = topo.byKname["md127"].encryption()
	assert.True(t, known)
	assert.False(t, encrypted)
}

func TestParseBlockPairsFilesystemNodesAndResolve(t *testing.T) {
	topo := loadRhel7PairsTopology(t)

	// md127 and the thin volume dm-8 are printed twice, listed once
	assert.Equal(t, []string{
		"zd0", "loop0", "loop1", "md0", "loop2", "md127", "loop3", "loop4",
		"nvme0n1p1", "nvme0n1p2",
		"nvme1n1p1", "dm-0", "dm-3", "dm-7", "dm-8", "nvme1n1p2",
		"nvme2n1p1", "nvme2n1p2",
		"nvme3n1p1", "dm-9", "nvme3n1p2",
	}, nodeKeys(topo.filesystemNodes()))

	assert.Equal(t, "dm-9", topo.resolve("/dev/mapper/g05crypt", "/mnt/crypt").key)
	assert.Equal(t, "dm-0", topo.resolve("/dev/mapper/vg--data-lv--lin", "/mnt/lvlin").key)
	assert.Equal(t, "dm-8", topo.resolve("/dev/vg-data/thinvol", "/mnt/thin").key)
	assert.Equal(t, "md127", topo.resolve("/dev/md127", "/mnt/md").key)
	assert.Equal(t, "nvme0n1p2", topo.resolve("/dev/root", "/").key)
}

func TestParseBlockPairsWithPathsFindsLuksDevices(t *testing.T) {
	data, err := os.ReadFile("testdata/lsblk_rhel7_pairs_paths.txt")
	require.NoError(t, err)
	parsed, err := parseBlockEntries(data)
	require.NoError(t, err)

	names := []string{}
	for _, d := range collectLuksDevices(parsed.Blockdevices) {
		names = append(names, d.Name)
	}
	assert.Equal(t, []string{"/dev/loop4", "/dev/nvme3n1p1"}, names)

	topo := buildBlockTopology(parsed.Blockdevices)
	assert.Equal(t, []string{"/dev/nvme3n1p1"}, nodeKeys(topo.byKname["/dev/dm-9"].parents))
}

func TestParseBlockPairsOrphanParentIsTopLevel(t *testing.T) {
	parsed, err := parseBlockEntries([]byte(`NAME="sdb1" KNAME="sdb1" PKNAME="sdb" TYPE="part" FSTYPE="ext4" LABEL="" UUID="" MOUNTPOINT="/data"` + "\n"))
	require.NoError(t, err)
	require.Len(t, parsed.Blockdevices, 1)
	assert.Equal(t, "sdb1", parsed.Blockdevices[0].Name)
}

func TestParseLsblkPairsLine(t *testing.T) {
	fields, err := parseLsblkPairsLine(`NAME="sda1" LABEL="my\x20disk\x22x" MOUNTPOINT="/mnt/a b" UUID=""`)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"NAME":       "sda1",
		"LABEL":      `my disk"x`,
		"MOUNTPOINT": "/mnt/a b",
		"UUID":       "",
	}, fields)

	_, err = parseLsblkPairsLine(`NAME="sda1" LABEL="unterminated`)
	assert.Error(t, err)
	_, err = parseLsblkPairsLine(`NAME="sda1" garbage`)
	assert.Error(t, err)
}
