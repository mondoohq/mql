// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// fakeProcConn is a minimal shared.Connection backed by an afero filesystem so
// we can exercise LinuxProcManager against a synthetic /proc tree.
type fakeProcConn struct {
	fs afero.Fs
}

func (c *fakeProcConn) ID() uint32                                 { return 0 }
func (c *fakeProcConn) ParentID() uint32                           { return 0 }
func (c *fakeProcConn) RunCommand(string) (*shared.Command, error) { return nil, nil }
func (c *fakeProcConn) FileInfo(string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, nil
}
func (c *fakeProcConn) FileSystem() afero.Fs              { return c.fs }
func (c *fakeProcConn) Name() string                      { return "fake" }
func (c *fakeProcConn) Type() shared.ConnectionType       { return "fake" }
func (c *fakeProcConn) Asset() *inventory.Asset           { return &inventory.Asset{} }
func (c *fakeProcConn) UpdateAsset(*inventory.Asset)      {}
func (c *fakeProcConn) Capabilities() shared.Capabilities { return shared.Capability_File }

func writeProcEntry(t *testing.T, fs afero.Fs, pid, name string) {
	t.Helper()
	require.NoError(t, afero.WriteFile(fs, "/proc/"+pid+"/cmdline", []byte(name+"\x00"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/proc/"+pid+"/status", []byte("Name:\t"+name+"\nState:\tS (sleeping)\nPid:\t"+pid+"\n"), 0o644))
}

type countingLinkFs struct {
	afero.Fs
	links       map[string]string
	fdDirOpens  int
	readlinkOps int
}

func (c *countingLinkFs) Open(path string) (afero.File, error) {
	if strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/fd") {
		c.fdDirOpens++
	}
	return c.Fs.Open(path)
}

func (c *countingLinkFs) ReadlinkIfPossible(path string) (string, error) {
	c.readlinkOps++
	link, ok := c.links[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return link, nil
}

func writeProcSockets(t *testing.T, fs afero.Fs, links map[string]string, pid string, inodes ...int64) {
	t.Helper()
	fdDir := filepath.Join("/proc", pid, "fd")
	require.NoError(t, fs.MkdirAll(fdDir, 0o755))
	for i := range inodes {
		fd := filepath.Join(fdDir, strconv.Itoa(i+3))
		require.NoError(t, afero.WriteFile(fs, fd, []byte{}, 0o644))
		links[fd] = "socket:[" + strconv.FormatInt(inodes[i], 10) + "]"
	}
}

func newLinuxProcManager(t *testing.T) *LinuxProcManager {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/proc", 0o755))
	writeProcEntry(t, fs, "1", "init")
	writeProcEntry(t, fs, "42", "bash")
	writeProcEntry(t, fs, "1337", "nginx")
	return &LinuxProcManager{conn: &fakeProcConn{fs: fs}}
}

// List() must return every pid it enumerated from /proc.
func TestLinuxProcManager_ListReturnsAllPids(t *testing.T) {
	lpm := newLinuxProcManager(t)

	procs, err := lpm.List()
	require.NoError(t, err)
	require.Len(t, procs, 3)

	pids := map[int64]bool{}
	for _, p := range procs {
		pids[p.Pid] = true
	}
	require.True(t, pids[1])
	require.True(t, pids[42])
	require.True(t, pids[1337])
}

// Process(pid) for a pid that does not exist must still report not-found,
// even though List() no longer re-stats enumerated pids.
func TestLinuxProcManager_ProcessNonexistentErrors(t *testing.T) {
	lpm := newLinuxProcManager(t)

	_, err := lpm.Process(999999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

// Process(pid) for an existing pid must succeed and return its data.
func TestLinuxProcManager_ProcessExistingSucceeds(t *testing.T) {
	lpm := newLinuxProcManager(t)

	proc, err := lpm.Process(42)
	require.NoError(t, err)
	require.Equal(t, int64(42), proc.Pid)
	require.Equal(t, "bash", proc.Command)
}

func TestLinuxProcManager_ProcessDefersSocketEnumeration(t *testing.T) {
	baseFs := afero.NewMemMapFs()
	require.NoError(t, baseFs.MkdirAll("/proc", 0o755))
	writeProcEntry(t, baseFs, "42", "bash")

	links := map[string]string{}
	writeProcSockets(t, baseFs, links, "42", 4201, 4202)

	fs := &countingLinkFs{Fs: baseFs, links: links}
	lpm := &LinuxProcManager{conn: &fakeProcConn{fs: fs}}

	proc, err := lpm.Process(42)
	require.NoError(t, err)
	require.NotNil(t, proc)
	assert.Equal(t, "bash", proc.Command)
	assert.Equal(t, 0, fs.fdDirOpens, "Process must not scan /proc/<pid>/fd")
	assert.Equal(t, 0, fs.readlinkOps, "Process must not resolve fd symlinks")

	socketInodesByPid, err := lpm.ListSocketInodesByProcess()
	require.NoError(t, err)
	assert.Greater(t, fs.fdDirOpens, 0, "socket scan should happen only when requested")
	assert.Greater(t, fs.readlinkOps, 0, "socket scan should happen only when requested")

	got, ok := socketInodesByPid[42]
	require.True(t, ok)
	require.NoError(t, got.Error)
	assert.ElementsMatch(t, []int64{4201, 4202}, got.Data)
}

func TestLinuxProcManager_SocketEnumerationIsDeferred(t *testing.T) {
	baseFs := afero.NewMemMapFs()
	require.NoError(t, baseFs.MkdirAll("/proc", 0o755))
	writeProcEntry(t, baseFs, "1", "init")
	writeProcEntry(t, baseFs, "42", "bash")

	links := map[string]string{}
	writeProcSockets(t, baseFs, links, "1", 1001)
	writeProcSockets(t, baseFs, links, "42", 4201, 4202)

	fs := &countingLinkFs{Fs: baseFs, links: links}
	lpm := &LinuxProcManager{conn: &fakeProcConn{fs: fs}}

	_, err := lpm.List()
	require.NoError(t, err)
	assert.Equal(t, 0, fs.fdDirOpens, "List must not scan /proc/<pid>/fd")
	assert.Equal(t, 0, fs.readlinkOps, "List must not resolve fd symlinks")

	socketInodesByPid, err := lpm.ListSocketInodesByProcess()
	require.NoError(t, err)
	assert.Greater(t, fs.fdDirOpens, 0, "socket scan should happen only when requested")
	assert.Greater(t, fs.readlinkOps, 0, "socket scan should happen only when requested")

	got, ok := socketInodesByPid[42]
	require.True(t, ok)
	require.NoError(t, got.Error)
	assert.ElementsMatch(t, []int64{4201, 4202}, got.Data)
}
