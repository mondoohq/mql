// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func TestNormalizeCgroupPath(t *testing.T) {
	assert.Equal(t, "/", normalizeCgroupPath("/sys/fs/cgroup"))
	assert.Equal(t, "/system.slice", normalizeCgroupPath("/sys/fs/cgroup/system.slice"))
	assert.Equal(t,
		"/user.slice/user-1000.slice",
		normalizeCgroupPath("/sys/fs/cgroup/user.slice/user-1000.slice"))
	assert.Equal(t,
		"/system.slice/docker-abc123.scope",
		normalizeCgroupPath("/sys/fs/cgroup/system.slice/docker-abc123.scope"))
}

func TestParentCgroupPath(t *testing.T) {
	// Root is its own parent — callers use this to break the self-link.
	assert.Equal(t, "/", parentCgroupPath("/"))
	assert.Equal(t, "/", parentCgroupPath("/system.slice"))
	assert.Equal(t, "/system.slice", parentCgroupPath("/system.slice/docker.scope"))
	assert.Equal(t,
		"/user.slice/user-1000.slice",
		parentCgroupPath("/user.slice/user-1000.slice/session-c1.scope"))
}

func TestCgroupUnitTypeFromPath(t *testing.T) {
	assert.Equal(t, "root", cgroupUnitTypeFromPath("/"))
	assert.Equal(t, "slice", cgroupUnitTypeFromPath("/system.slice"))
	assert.Equal(t, "slice", cgroupUnitTypeFromPath("/user.slice/user-1000.slice"))
	assert.Equal(t, "scope", cgroupUnitTypeFromPath("/system.slice/docker-abc123.scope"))
	assert.Equal(t, "service", cgroupUnitTypeFromPath("/system.slice/nginx.service"))
	// Unrecognized leaves (e.g. raw kubelet/podman trees) fall through to "other".
	assert.Equal(t, "other", cgroupUnitTypeFromPath("/kubepods/burstable"))
}

func TestParseCgroupMax(t *testing.T) {
	// "max" is the kernel's literal for "no limit"; we surface it as -1
	// so MQL queries can use `< 0` to mean unlimited.
	assert.Equal(t, int64(-1), parseCgroupMax("max"))
	assert.Equal(t, int64(-1), parseCgroupMax(""))
	assert.Equal(t, int64(-1), parseCgroupMax("   "))
	// Missing controllers' files also read as "unlimited" — same outcome.
	assert.Equal(t, int64(-1), parseCgroupMax("not a number"))
	assert.Equal(t, int64(1073741824), parseCgroupMax("1073741824"))
	assert.Equal(t, int64(1073741824), parseCgroupMax(" 1073741824 "))
}

func TestParseCgroupInt(t *testing.T) {
	assert.Equal(t, int64(0), parseCgroupInt("", 0))
	assert.Equal(t, int64(100), parseCgroupInt("", 100))
	assert.Equal(t, int64(100), parseCgroupInt("garbage", 100))
	assert.Equal(t, int64(42), parseCgroupInt("42", 0))
	assert.Equal(t, int64(42), parseCgroupInt("  42  ", 0))
}

func TestParseCpuMax(t *testing.T) {
	// Default values for an empty file (controller not enabled).
	q, p := parseCpuMax("")
	assert.Equal(t, int64(-1), q)
	assert.Equal(t, int64(100000), p)

	// `max <period>` — quota unlimited, custom period.
	q, p = parseCpuMax("max 100000")
	assert.Equal(t, int64(-1), q)
	assert.Equal(t, int64(100000), p)

	// 50% CPU cap.
	q, p = parseCpuMax("50000 100000")
	assert.Equal(t, int64(50000), q)
	assert.Equal(t, int64(100000), p)

	// quota-only (rare, but defensible — keep period at default).
	q, p = parseCpuMax("50000")
	assert.Equal(t, int64(50000), q)
	assert.Equal(t, int64(100000), p)
}

func TestPidsAsAny(t *testing.T) {
	// Numeric strings parse to int64; non-numeric tokens are dropped so
	// junk in a cgroup.procs file can't crash MQL.
	out := pidsAsAny([]string{"1234", "1235", "abc", "1236"})
	require.Len(t, out, 3)
	assert.Equal(t, int64(1234), out[0])
	assert.Equal(t, int64(1235), out[1])
	assert.Equal(t, int64(1236), out[2])

	assert.Empty(t, pidsAsAny(nil))
	assert.Empty(t, pidsAsAny([]string{}))
}

func TestStringsAsAny(t *testing.T) {
	out := stringsAsAny([]string{"memory", "cpu", "io"})
	require.Len(t, out, 3)
	assert.Equal(t, "memory", out[0])
	assert.Equal(t, "io", out[2])
	assert.Empty(t, stringsAsAny(nil))
}

// writeCgroupDir lays down one cgroup v2 node in a fake filesystem.
func writeCgroupDir(t *testing.T, fs afero.Fs, dir string, attrs map[string]string) {
	t.Helper()
	require.NoError(t, fs.MkdirAll(dir, 0o755))
	for name, content := range attrs {
		require.NoError(t, afero.WriteFile(fs, dir+"/"+name, []byte(content), 0o444))
	}
}

func TestDetectCgroupVersion(t *testing.T) {
	// Unified hierarchy: the marker file at the mount point.
	v2 := afero.NewMemMapFs()
	writeCgroupDir(t, v2, "/sys/fs/cgroup", map[string]string{"cgroup.controllers": "cpu memory\n"})
	assert.Equal(t, int64(2), detectCgroupVersion(v2))

	// v1 ships per-controller directories and no marker file.
	v1 := afero.NewMemMapFs()
	require.NoError(t, v1.MkdirAll("/sys/fs/cgroup/memory", 0o755))
	require.NoError(t, v1.MkdirAll("/sys/fs/cgroup/cpu", 0o755))
	assert.Equal(t, int64(1), detectCgroupVersion(v1))

	// Image/tar scans have no /sys at all.
	assert.Equal(t, int64(0), detectCgroupVersion(afero.NewMemMapFs()))
}

func TestWalkCgroupFS(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Root. cgroup.procs is one PID per line on a real system.
	writeCgroupDir(t, fs, "/sys/fs/cgroup", map[string]string{
		"cgroup.controllers": "cpuset cpu io memory hugetlb pids rdma misc\n",
		"cgroup.type":        "domain\n",
		"memory.max":         "max\n",
		"memory.current":     "104857600\n",
		"cpu.max":            "max 100000\n",
		"cpu.weight":         "100\n",
		"pids.current":       "42\n",
		"cgroup.procs":       "1\n",
	})
	writeCgroupDir(t, fs, "/sys/fs/cgroup/system.slice", map[string]string{
		"cgroup.controllers": "cpuset cpu io memory pids\n",
		"memory.max":         "8589934592\n",
		"cpu.max":            "200000 100000\n",
		"cgroup.procs":       "",
	})
	writeCgroupDir(t, fs, "/sys/fs/cgroup/system.slice/nginx.service", map[string]string{
		"cgroup.controllers": "\n",
		"memory.max":         "104857600\n",
		"cgroup.procs":       "1234\n1235\n1236\n1237\n",
	})
	// A plain directory that is not a cgroup must not become a node.
	require.NoError(t, fs.MkdirAll("/sys/fs/cgroup/system.slice/not-a-cgroup", 0o755))

	parsed, err := walkCgroupFS(fs)
	require.NoError(t, err)
	require.Len(t, parsed, 3)

	// Depth-first from the root, root first.
	assert.Equal(t, "/sys/fs/cgroup", parsed[0].rawPath)
	assert.Equal(t, "/sys/fs/cgroup/system.slice", parsed[1].rawPath)
	assert.Equal(t, "/sys/fs/cgroup/system.slice/nginx.service", parsed[2].rawPath)

	assert.Equal(t, "cpuset cpu io memory hugetlb pids rdma misc", parsed[0].attrs["cgroup.controllers"])
	assert.Equal(t, "domain", parsed[0].attrs["cgroup.type"])
	assert.Equal(t, "104857600", parsed[0].attrs["memory.current"])
	assert.Equal(t, "max 100000", parsed[0].attrs["cpu.max"])

	// Absent attribute files stay absent rather than becoming "".
	_, ok := parsed[1].attrs["cgroup.type"]
	assert.False(t, ok, "an attribute file that does not exist must not be recorded")
	assert.Equal(t, "", parsed[1].attrs["cgroup.procs"], "an empty cgroup.procs file reads as empty")

	// The multi-line cgroup.procs file collapses to the space-separated
	// form buildCgroupResource splits on.
	assert.Equal(t, "1234 1235 1236 1237", parsed[2].attrs["cgroup.procs"])
}

func TestWalkCgroupFSDepthBound(t *testing.T) {
	fs := afero.NewMemMapFs()
	dir := "/sys/fs/cgroup"
	for i := 0; i <= cgroupWalkMaxDepth+1; i++ {
		writeCgroupDir(t, fs, dir, map[string]string{"cgroup.controllers": "memory\n"})
		dir += "/level"
	}

	parsed, err := walkCgroupFS(fs)
	require.NoError(t, err)

	// Root plus cgroupWalkMaxDepth levels below it; the level past the
	// bound is not collected.
	require.Len(t, parsed, cgroupWalkMaxDepth+1)
	assert.Equal(t,
		"/sys/fs/cgroup/level/level/level",
		parsed[cgroupWalkMaxDepth].rawPath)
}

func TestWalkCgroupFSUnreadableRoot(t *testing.T) {
	// The regression this guards: a target where the cgroup root cannot
	// be read used to report version 2 with zero controllers, asserting
	// as fact that a cgroup v2 host has no controllers. It must be an
	// error instead.
	_, err := walkCgroupFS(afero.NewMemMapFs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), cgroupRoot)
}

func TestFlattenCgroupAttr(t *testing.T) {
	// cgroup.procs is one PID per line; callers split on whitespace.
	assert.Equal(t, "1234 1235 1236", flattenCgroupAttr([]byte("1234\n1235\n1236\n")))
	assert.Equal(t, "max", flattenCgroupAttr([]byte("max\n")))
	assert.Equal(t, "", flattenCgroupAttr([]byte("")))
	assert.Equal(t, "", flattenCgroupAttr([]byte("\n")))
	assert.Equal(t, "50000 100000", flattenCgroupAttr([]byte("50000 100000\n")))
}

// /proc/cgroups from a RHEL 8.10 host booted with cgroup v1.
const rhel8ProcCgroups = `#subsys_name	hierarchy	num_cgroups	enabled
cpuset	8	1	1
cpu	4	78	1
cpuacct	4	78	1
blkio	9	78	1
memory	11	185	1
devices	12	78	1
freezer	5	1	1
net_cls	10	1	1
perf_event	3	1	1
net_prio	10	1	1
hugetlb	2	1	1
pids	6	86	1
rdma	7	1	1
`

func TestParseProcCgroups(t *testing.T) {
	assert.Equal(t, []string{
		"cpuset", "cpu", "cpuacct", "blkio", "memory", "devices", "freezer",
		"net_cls", "perf_event", "net_prio", "hugetlb", "pids", "rdma",
	}, parseProcCgroups(rhel8ProcCgroups))

	// a controller on no v1 hierarchy (hierarchy 0, as on a hybrid host where
	// it sits on the unified one) or disabled with cgroup_disable= is not
	// available to v1 cgroups
	assert.Equal(t, []string{"cpu"}, parseProcCgroups("#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpu\t4\t78\t1\nmemory\t0\t1\t1\nrdma\t7\t1\t0\n"))

	assert.Empty(t, parseProcCgroups(""))
}

// cgroupFsConn serves a mock connection's files from fs.
type cgroupFsConn struct {
	mockConn
	fs afero.Fs
}

func (c *cgroupFsConn) FileSystem() afero.Fs { return c.fs }

// On cgroup v1 (RHEL 7 and 8, Alma 8) controllers read [] because only the v2
// marker file was consulted, and list read [] as if the host ran no cgroups.
func TestCgroupsV1(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/sys/fs/cgroup/memory", 0o755))
	require.NoError(t, afero.WriteFile(fs, "/proc/cgroups", []byte(rhel8ProcCgroups), 0o444))

	runtime := &plugin.Runtime{
		Connection: &cgroupFsConn{fs: fs},
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	raw, err := CreateResource(runtime, "cgroups", nil)
	require.NoError(t, err)
	cg := raw.(*mqlCgroups)

	version := cg.GetVersion()
	require.NoError(t, version.Error)
	assert.Equal(t, int64(1), version.Data)

	controllers := cg.GetControllers()
	require.NoError(t, controllers.Error)
	assert.Len(t, controllers.Data, 13)
	assert.Contains(t, controllers.Data, "memory")

	list := cg.GetList()
	require.NoError(t, list.Error)
	assert.Nil(t, list.Data)
	assert.True(t, list.IsNull())

	root := cg.GetRoot()
	require.NoError(t, root.Error)
	assert.Nil(t, root.Data)
}

// A v1 host whose /proc/cgroups cannot be read fails controllers, not version.
func TestCgroupsV1UnreadableProcCgroups(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/sys/fs/cgroup/memory", 0o755))

	runtime := &plugin.Runtime{
		Connection: &cgroupFsConn{fs: fs},
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	raw, err := CreateResource(runtime, "cgroups", nil)
	require.NoError(t, err)
	cg := raw.(*mqlCgroups)

	assert.Equal(t, int64(1), cg.GetVersion().Data)
	assert.Error(t, cg.GetControllers().Error)
}
