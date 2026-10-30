// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package zfs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/ubuntu16.04 and testdata/ubuntu18.04 are real output from Ubuntu
// 16.04 (ZFS on Linux 0.6.5.6) and Ubuntu 18.04 (ZFS on Linux 0.7.5) with a
// pool "tank" on a disk partition and a pool "mpool", a mirror of two files.
// Neither release has JSON output, `zfs version`, or the -p and -s flags of
// zpool status. 0.6.5 prints capacity with a percent sign even with -p.

func TestParsePoolsText_Ubuntu1604PercentSign(t *testing.T) {
	pools, err := ParsePoolsText(fixture(t, "ubuntu16.04", "zpool_get_all.txt"))
	require.NoError(t, err)
	pools = sortPools(pools)
	require.Len(t, pools, 2)

	p := pools[0]
	assert.Equal(t, "mpool", p.Name)
	assert.Equal(t, "16867545691036494997", p.GUID)
	assert.Equal(t, int64(251658240), p.Size)
	assert.Equal(t, int64(65536), p.Allocated)
	assert.Equal(t, int64(0), p.PercentUsed)
	require.NotNil(t, p.Fragmentation)
	assert.Equal(t, int64(1), *p.Fragmentation)
	assert.Equal(t, 1.0, p.Dedupratio)

	assert.Equal(t, "tank", pools[1].Name)
	assert.Equal(t, "5719591405464364946", pools[1].GUID)
}

func TestParsePercent(t *testing.T) {
	for in, want := range map[string]int64{"37%": 37, "37": 37, "0%": 0, "-": 0, "": 0} {
		got, err := parsePercent(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	_, err := parsePercent("x%")
	assert.Error(t, err)
}

func TestParseCount(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "999": 999, "1K": 1024, "1.50K": 1536, "3M": 3 << 20} {
		got, err := parseCount(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"was", "K", "1.5Q", "-1K"} {
		_, err := parseCount(in)
		assert.Error(t, err, in)
	}
}

// poolSection returns the output of `zpool status` for one pool, cut from the
// output for all pools.
func poolSection(t *testing.T, output, pool string) string {
	t.Helper()
	i := strings.Index(output, "  pool: "+pool+"\n")
	require.GreaterOrEqual(t, i, 0, pool)
	return output[i:]
}

func TestParseVdevsTextPlain_Ubuntu1804(t *testing.T) {
	short := fixture(t, "ubuntu18.04", "zpool_status_short.txt")
	full := fixture(t, "ubuntu18.04", "zpool_status_fullpaths.txt")

	// A disk partition keeps its /dev path, it is not a Solaris /dev/dsk disk.
	vdevs, err := ParseVdevsTextPlain(poolSection(t, short, "tank"), poolSection(t, full, "tank"))
	require.NoError(t, err)
	require.Len(t, vdevs, 1)
	assert.Equal(t, Vdev{Name: "nvme3n1p2", Type: "disk", State: "ONLINE", Path: "/dev/nvme3n1p2"}, vdevs[0])

	vdevs, err = ParseVdevsTextPlain(poolSection(t, short, "mpool"), poolSection(t, full, "mpool"))
	require.NoError(t, err)
	require.Len(t, vdevs, 1)
	assert.Equal(t, "mirror-0", vdevs[0].Name)
	assert.Equal(t, "mirror", vdevs[0].Type)
	require.Len(t, vdevs[0].Devices, 2)
	assert.Equal(t, "/var/lib/g05/z1.img", vdevs[0].Devices[0].Path)
	assert.Equal(t, "file", vdevs[0].Devices[0].Type)

	// Oracle Solaris has no -P: bare disk names resolve under /dev/dsk.
	vdevs, err = ParseVdevsTextPlain(fixture(t, "solaris11.4", "zpool_status_rpool.txt"), "")
	require.NoError(t, err)
	require.NotEmpty(t, vdevs)
	assert.True(t, strings.HasPrefix(vdevs[0].Path, "/dev/dsk/"), vdevs[0].Path)
}

func TestStatusVdev_NoSlowColumn(t *testing.T) {
	// Without -s, a note follows CKSUM directly; it is not a slow I/O count.
	v, err := statusVdev(
		strings.Fields("sdb UNAVAIL 1.2K 0 3 was /dev/sdb1"),
		strings.Fields("/dev/sdb UNAVAIL 1.2K 0 3 was /dev/sdb1"),
		3,
	)
	require.NoError(t, err)
	assert.Equal(t, int64(1229), v.ReadErrors)
	assert.Equal(t, int64(3), v.ChecksumErrors)
	assert.Equal(t, int64(0), v.SlowIOs)
	assert.Equal(t, "/dev/sdb1", v.Path)
}
