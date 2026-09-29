// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package zfs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/solaris11.4 is real output from Oracle Solaris 11.4.86 (OCI): the
// image's root pool "rpool" on one disk, plus a file-backed pool "mqltest"
// (a mirror of two files and a lone file vdev) holding a gzip filesystem with
// dedup on, three copies of one file, and a snapshot. Solaris has no JSON
// output, no `zfs version`, and a `zpool status` without -p, -s or -P.

func TestSolarisPoolsText(t *testing.T) {
	pools, err := ParsePoolsText(fixture(t, "solaris11.4", "zpool_get_all.txt"))
	require.NoError(t, err)
	pools = sortPools(pools)
	require.Len(t, pools, 2)

	p := pools[0]
	assert.Equal(t, "mqltest", p.Name)
	assert.Equal(t, "13795439755298816899", p.GUID)
	assert.Equal(t, "ONLINE", p.Health)
	assert.Equal(t, int64(257697792), p.Size)
	assert.Equal(t, int64(1319936), p.Allocated)
	assert.Equal(t, int64(256377856), p.Free)
	// "300" in hundredths: three copies of one file
	assert.Equal(t, 3.0, p.Dedupratio)
	// Solaris has no fragmentation property
	assert.Nil(t, p.Fragmentation)

	assert.Equal(t, "rpool", pools[1].Name)
	assert.Equal(t, 1.0, pools[1].Dedupratio)
	assert.True(t, pools[1].Autoexpand)
}

func TestSolarisDatasetsText(t *testing.T) {
	// The image's com.oracle.diskimage:original_guid user property ends in a
	// newline, splitting its row across two lines on every dataset.
	datasets, err := ParseDatasetsText(fixture(t, "solaris11.4", "zfs_get_all.txt"))
	require.NoError(t, err)
	require.Len(t, datasets, 24)

	byName := map[string]Dataset{}
	for _, d := range datasets {
		byName[d.Name] = d
	}
	assert.NotContains(t, byName, "")

	fs, ok := byName["mqltest/fs"]
	require.True(t, ok)
	assert.Equal(t, "filesystem", fs.Type)
	assert.Equal(t, "gzip", fs.Compression)
	assert.Equal(t, 1.10, fs.Compressratio)
	assert.Equal(t, int64(3253760), fs.Used)
	assert.Equal(t, int64(222823424), fs.Available)
	assert.Equal(t, int64(3234304), fs.Referenced)
	assert.Equal(t, int64(131072), fs.Recordsize)
	assert.Equal(t, "/mqltest/fs", fs.Mountpoint)
	assert.True(t, fs.Mounted)
	require.NotNil(t, fs.Creation)
	assert.Equal(t, time.Unix(1790714808, 0), *fs.Creation)

	snap, ok := byName["mqltest/fs@snap1"]
	require.True(t, ok)
	assert.Equal(t, "snapshot", snap.Type)
}

func TestSolarisMultilineValue(t *testing.T) {
	in := "rpool\tatime\ton\tdefault\n" +
		"rpool\tcom.oracle.diskimage:original_guid\t5411661290718900126\n" +
		"\tlocal\n" +
		"rpool\tzoned\toff\tdefault\n"
	byName, err := parseGetText(in)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"atime":                              "on",
		"com.oracle.diskimage:original_guid": "5411661290718900126\n",
		"zoned":                              "off",
	}, byName["rpool"])

	_, err = parseGetText("rpool\tatime\ton\n")
	assert.Error(t, err, "a row that never completes is still an error")
}

func TestSolarisVdevsText(t *testing.T) {
	vdevs, err := ParseVdevsTextSolaris(fixture(t, "solaris11.4", "zpool_status_mqltest.txt"))
	require.NoError(t, err)
	require.Len(t, vdevs, 2)

	assert.Equal(t, "mirror-0", vdevs[0].Name)
	assert.Equal(t, "mirror", vdevs[0].Type)
	assert.Equal(t, "", vdevs[0].Path)
	require.Len(t, vdevs[0].Devices, 2)
	assert.Equal(t, "/var/tmp/zt/a", vdevs[0].Devices[0].Path)
	assert.Equal(t, "file", vdevs[0].Devices[0].Type)
	assert.Equal(t, "ONLINE", vdevs[0].Devices[0].State)

	assert.Equal(t, "/var/tmp/zt/c", vdevs[1].Path)
	assert.Equal(t, "file", vdevs[1].Type)

	vdevs, err = ParseVdevsTextSolaris(fixture(t, "solaris11.4", "zpool_status_rpool.txt"))
	require.NoError(t, err)
	require.Len(t, vdevs, 1)
	assert.Equal(t, "c0t6054BB6D07F2401EB09235A50F901EA4d0", vdevs[0].Name)
	assert.Equal(t, "/dev/dsk/c0t6054BB6D07F2401EB09235A50F901EA4d0", vdevs[0].Path)
	assert.Equal(t, "disk", vdevs[0].Type)
}

// OpenZFS writes "-" for a pool without the spacemap_histogram feature. That
// is no fragmentation figure at all, not 0%.
func TestPoolFragmentationUnreported(t *testing.T) {
	pools, err := ParsePoolsText("tank\tfragmentation\t-\t-\ntank\tsize\t100\t-\n")
	require.NoError(t, err)
	require.Len(t, pools, 1)
	assert.Nil(t, pools[0].Fragmentation)
}

func TestSolarisPoolVersion(t *testing.T) {
	v, ok := ParseSolarisPoolVersion(fixture(t, "solaris11.4", "zpool_upgrade_v.txt"))
	require.True(t, ok)
	assert.Equal(t, "53", v)

	// illumos reports feature flags instead of a version number
	_, ok = ParseSolarisPoolVersion("This system supports ZFS pool feature flags.\n")
	assert.False(t, ok)
}
