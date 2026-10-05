// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"testing"

	"github.com/spf13/afero"
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

// A kernel thread has an empty cmdline. Its argv was read and is empty, so it
// must not be nil: flags would take nil for an argv it has yet to read and
// run a command per kernel thread to read it again.
func TestLinuxProcManager_KernelThreadArgvIsEmptyNotUnknown(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/proc/2/cmdline", nil, 0o444))
	require.NoError(t, afero.WriteFile(fs, "/proc/2/comm", []byte("kthreadd\n"), 0o444))
	require.NoError(t, afero.WriteFile(fs, "/proc/2/status", []byte("Name:\tkthreadd\nState:\tS (sleeping)\nPid:\t2\n"), 0o444))
	lpm := &LinuxProcManager{conn: &fakeProcConn{fs: fs}}

	proc, err := lpm.Process(2)
	require.NoError(t, err)
	require.Equal(t, "kthreadd", proc.Command)
	require.NotNil(t, proc.Argv)
	require.Empty(t, proc.Argv)
}
