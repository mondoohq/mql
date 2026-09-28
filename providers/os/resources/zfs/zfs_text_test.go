// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package zfs

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures in testdata/ are real command output:
//   - freebsd13.5: OpenZFS 2.1.15, file-backed pool "mqltest" (mirror of two
//     files) with a filesystem and a snapshot. No JSON output.
//   - freebsd14.5: OpenZFS 2.2.9, ZFS root pool "zroot" on one disk
//     partition. No JSON output.
//   - freebsd15.1: OpenZFS 2.4.2, file-backed pool "mqltest" with mirror,
//     raidz1, special, log, cache, and spare vdevs, plus a filesystem,
//     snapshot, bookmark, clone, and volume. Captured in both JSON and text
//     form from the same pool state, to prove the two parsers agree.

func fixture(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, name))
	require.NoError(t, err)
	return string(data)
}

func sortPools(p []Pool) []Pool {
	sort.Slice(p, func(i, j int) bool { return p[i].Name < p[j].Name })
	return p
}

func sortDatasets(d []Dataset) []Dataset {
	sort.Slice(d, func(i, j int) bool { return d[i].Name < d[j].Name })
	return d
}

func sortVdevs(v []Vdev) []Vdev {
	sort.Slice(v, func(i, j int) bool { return v[i].Name < v[j].Name })
	for i := range v {
		v[i].Devices = sortVdevs(v[i].Devices)
	}
	return v
}

func TestTextMatchesJSON_Pools(t *testing.T) {
	fromJSON, err := ParsePools(fixture(t, "freebsd15.1", "zpool_get_all.json"))
	require.NoError(t, err)
	fromText, err := ParsePoolsText(fixture(t, "freebsd15.1", "zpool_get_all.txt"))
	require.NoError(t, err)

	require.Len(t, fromJSON, 1)
	assert.Equal(t, sortPools(fromJSON), sortPools(fromText))
}

func TestTextMatchesJSON_Datasets(t *testing.T) {
	fromJSON, err := ParseDatasets(fixture(t, "freebsd15.1", "zfs_get_all.json"))
	require.NoError(t, err)
	fromText, err := ParseDatasetsText(fixture(t, "freebsd15.1", "zfs_get_all.txt"))
	require.NoError(t, err)

	require.Len(t, fromJSON, 6)
	assert.Equal(t, sortDatasets(fromJSON), sortDatasets(fromText))
}

func TestTextMatchesJSON_Properties(t *testing.T) {
	for _, pair := range [][2]string{
		{"zpool_get_all.json", "zpool_get_all.txt"},
		{"zfs_get_fs.json", "zfs_get_fs.txt"},
	} {
		fromJSON, err := ParseProperties(fixture(t, "freebsd15.1", pair[0]))
		require.NoError(t, err)
		fromText, err := ParsePropertiesText(fixture(t, "freebsd15.1", pair[1]))
		require.NoError(t, err)

		assert.NotEmpty(t, fromJSON)
		assert.Equal(t, fromJSON, fromText, pair[1])
	}

	// A user property whose value holds a space survives the text form.
	props, err := ParsePropertiesText(fixture(t, "freebsd15.1", "zfs_get_fs.txt"))
	require.NoError(t, err)
	assert.Equal(t, "a b", props["mql:note"])
}

func TestTextMatchesJSON_Vdevs(t *testing.T) {
	fromJSON, err := ParseVdevs(fixture(t, "freebsd15.1", "zpool_status.json"))
	require.NoError(t, err)
	fromText, err := ParseVdevsText(
		fixture(t, "freebsd15.1", "zpool_status_short.txt"),
		fixture(t, "freebsd15.1", "zpool_status_fullpaths.txt"),
	)
	require.NoError(t, err)

	// mirror-0 and raidz1-1; special, logs, cache, and spares are left out
	require.Len(t, fromJSON, 2)
	assert.Equal(t, sortVdevs(fromJSON), sortVdevs(fromText))
}

func TestParsePoolsText_FreeBSD14(t *testing.T) {
	pools, err := ParsePoolsText(fixture(t, "freebsd14.5", "zpool_get_all.txt"))
	require.NoError(t, err)
	require.Len(t, pools, 1)

	p := pools[0]
	assert.Equal(t, "zroot", p.Name)
	assert.Equal(t, "8437312393084458689", p.GUID)
	assert.Equal(t, "ONLINE", p.Health)
	assert.Equal(t, int64(57445187584), p.Size)
	assert.Equal(t, int64(15583772672), p.Allocated)
	assert.Equal(t, int64(41861414912), p.Free)
	assert.Equal(t, int64(2), p.Fragmentation)
	assert.Equal(t, int64(27), p.PercentUsed)
	assert.InDelta(t, 1.0, p.Dedupratio, 0.001)
	assert.False(t, p.Readonly)
	assert.False(t, p.Autotrim)
}

func TestParseDatasetsText_FreeBSD14(t *testing.T) {
	datasets, err := ParseDatasetsText(fixture(t, "freebsd14.5", "zfs_get_all.txt"))
	require.NoError(t, err)
	require.Len(t, datasets, 15)

	var root *Dataset
	for i := range datasets {
		if datasets[i].Name == "zroot/ROOT/default" {
			root = &datasets[i]
		}
	}
	require.NotNil(t, root)
	assert.Equal(t, "filesystem", root.Type)
	assert.Equal(t, "/", root.Mountpoint)
	assert.True(t, root.Mounted)
	assert.Equal(t, int64(15460552704), root.Used)
	assert.Equal(t, int64(40083922944), root.Available)
	assert.Equal(t, int64(131072), root.Recordsize)
	assert.Equal(t, "off", root.Compression)
	assert.Equal(t, "off", root.Encryption)
	assert.Equal(t, "", root.Origin)
}

func TestParseDatasetsText_FreeBSD13(t *testing.T) {
	datasets, err := ParseDatasetsText(fixture(t, "freebsd13.5", "zfs_get_all.txt"))
	require.NoError(t, err)
	datasets = sortDatasets(datasets)
	require.Len(t, datasets, 3)

	fs := datasets[1]
	assert.Equal(t, "mqltest/fs", fs.Name)
	assert.Equal(t, "gzip", fs.Compression)

	snap := datasets[2]
	assert.Equal(t, "mqltest/fs@snap1", snap.Name)
	assert.Equal(t, "snapshot", snap.Type)
	assert.Equal(t, "", snap.Mountpoint)
	assert.False(t, snap.Mounted)
	require.NotNil(t, snap.Creation)
	assert.Equal(t, time.Unix(1790569054, 0), *snap.Creation)
}

func TestParseVdevsText_SingleDisk(t *testing.T) {
	// FreeBSD 14.5 root pool: one disk partition directly under the root vdev.
	vdevs, err := ParseVdevsText(
		fixture(t, "freebsd14.5", "zpool_status_short.txt"),
		fixture(t, "freebsd14.5", "zpool_status_fullpaths.txt"),
	)
	require.NoError(t, err)
	require.Len(t, vdevs, 1)
	assert.Equal(t, Vdev{
		Name:  "nda0p3",
		Type:  "disk",
		State: "ONLINE",
		Path:  "/dev/nda0p3",
	}, vdevs[0])
}

func TestParseVdevsText_Mirror(t *testing.T) {
	vdevs, err := ParseVdevsText(
		fixture(t, "freebsd13.5", "zpool_status_short.txt"),
		fixture(t, "freebsd13.5", "zpool_status_fullpaths.txt"),
	)
	require.NoError(t, err)
	require.Len(t, vdevs, 1)

	m := vdevs[0]
	assert.Equal(t, "mirror-0", m.Name)
	assert.Equal(t, "mirror", m.Type)
	assert.Equal(t, "", m.Path)
	require.Len(t, m.Devices, 2)
	assert.Equal(t, "/var/tmp/mqlzfs/f1.img", m.Devices[0].Name)
	assert.Equal(t, "/var/tmp/mqlzfs/f1.img", m.Devices[0].Path)
	assert.Equal(t, "file", m.Devices[0].Type)
	assert.Equal(t, "/var/tmp/mqlzfs/f2.img", m.Devices[1].Name)
}

func TestParseVdevsText_DegradedWithErrors(t *testing.T) {
	// Layout of a degraded raidz2 pool with a missing disk, as zpool status
	// prints it.
	short := `  pool: tank
 state: DEGRADED
config:

	NAME                      STATE     READ WRITE CKSUM  SLOW
	tank                      DEGRADED     0     0     0     0
	  raidz2-0                DEGRADED     0     0     0     0
	    ada1                  ONLINE       3     1    12     5
	    9876543210123456789   UNAVAIL      0     0     0     0  was /dev/ada2
	    ada3                  ONLINE       0     0     0     0
	logs
	  ada4                    ONLINE       0     0     0     0

errors: No known data errors
`
	full := `  pool: tank
 state: DEGRADED
config:

	NAME                      STATE     READ WRITE CKSUM  SLOW
	tank                      DEGRADED     0     0     0     0
	  raidz2-0                DEGRADED     0     0     0     0
	    /dev/ada1             ONLINE       3     1    12     5
	    9876543210123456789   UNAVAIL      0     0     0     0  was /dev/ada2
	    /dev/ada3             ONLINE       0     0     0     0
	logs
	  /dev/ada4               ONLINE       0     0     0     0

errors: No known data errors
`
	vdevs, err := ParseVdevsText(short, full)
	require.NoError(t, err)
	require.Len(t, vdevs, 1)

	g := vdevs[0]
	assert.Equal(t, "raidz2-0", g.Name)
	assert.Equal(t, "raidz", g.Type)
	assert.Equal(t, "DEGRADED", g.State)
	require.Len(t, g.Devices, 3)

	assert.Equal(t, Vdev{
		Name: "ada1", Type: "disk", State: "ONLINE", Path: "/dev/ada1",
		ReadErrors: 3, WriteErrors: 1, ChecksumErrors: 12, SlowIOs: 5,
	}, g.Devices[0])
	assert.Equal(t, "9876543210123456789", g.Devices[1].Name)
	assert.Equal(t, "UNAVAIL", g.Devices[1].State)
	assert.Equal(t, "/dev/ada2", g.Devices[1].Path)
	assert.Equal(t, "disk", g.Devices[1].Type)
}

func TestParseVdevsText_Empty(t *testing.T) {
	vdevs, err := ParseVdevsText("", "")
	require.NoError(t, err)
	assert.Nil(t, vdevs)

	vdevs, err = ParseVdevsText("no pools available\n", "no pools available\n")
	require.NoError(t, err)
	assert.Nil(t, vdevs)
}

func TestParseVdevsText_MismatchedOutputs(t *testing.T) {
	_, err := ParseVdevsText(
		fixture(t, "freebsd15.1", "zpool_status_short.txt"),
		fixture(t, "freebsd14.5", "zpool_status_fullpaths.txt"),
	)
	assert.Error(t, err)
}

func TestParseVdevsText_BadCounter(t *testing.T) {
	status := "config:\n\n\tNAME STATE READ WRITE CKSUM\n\ttank ONLINE 0 0 0\n\t  ada1 ONLINE 1.2K 0 0\n"
	_, err := ParseVdevsText(status, status)
	assert.Error(t, err)
}

func TestGroupVdevType(t *testing.T) {
	assert.Equal(t, "mirror", groupVdevType("mirror-0"))
	assert.Equal(t, "raidz", groupVdevType("raidz1-1"))
	assert.Equal(t, "raidz", groupVdevType("raidz3-12"))
	assert.Equal(t, "draid", groupVdevType("draid2:4d:6c:1s-0"))
	assert.Equal(t, "spare", groupVdevType("spare-3"))
	assert.Equal(t, "replacing", groupVdevType("replacing-0"))
}

func TestEmptyTextOutput(t *testing.T) {
	// FreeBSD 13.5 with no pools: zpool get and zfs get print nothing and exit 0.
	pools, err := ParsePoolsText("")
	require.NoError(t, err)
	assert.Nil(t, pools)

	datasets, err := ParseDatasetsText("")
	require.NoError(t, err)
	assert.Nil(t, datasets)
}

func TestEmptyJSONOutput(t *testing.T) {
	// FreeBSD 15.1 with no pools.
	pools, err := ParsePools(`{"output_version":{"command":"zpool get","vers_major":0,"vers_minor":1},"pools":{}}`)
	require.NoError(t, err)
	assert.Nil(t, pools)

	datasets, err := ParseDatasets(`{"output_version":{"command":"zfs get","vers_major":0,"vers_minor":1},"datasets":{}}`)
	require.NoError(t, err)
	assert.Nil(t, datasets)
}

func TestParseGetText_Malformed(t *testing.T) {
	_, err := ParsePoolsText("zroot\tsize\n")
	assert.Error(t, err)
}

func TestParseGetText_TabInValue(t *testing.T) {
	props, err := ParsePropertiesText("tank/fs\tmql:note\ta\tb\tlocal\n")
	require.NoError(t, err)
	assert.Equal(t, "a\tb", props["mql:note"])
}

func TestIsJSONUnsupported(t *testing.T) {
	assert.True(t, IsJSONUnsupported(fixture(t, "freebsd13.5", "zpool_get_rejected_j.stderr")))
	assert.True(t, IsJSONUnsupported(fixture(t, "freebsd14.5", "zpool_get_rejected_j.stderr")))
	assert.False(t, IsJSONUnsupported("cannot open 'tank': no such pool\n"))
	assert.False(t, IsJSONUnsupported("sh: zpool: not found\n"))
}
