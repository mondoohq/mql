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

// The kernel cuts the Name in /proc/<pid>/status to 15 characters; the
// executable is the full name from the command's first argument, as over SSH
// (mondoohq/mql#11185).
func TestFullExecutableName(t *testing.T) {
	tests := []struct {
		name, status, cmdline, want string
	}{
		{"cut name, absolute path", "kube-controller", "/usr/local/bin/kube-controller-manager\x00--kubeconfig=/etc/kubernetes/controller-manager.conf\x00", "kube-controller-manager"},
		{"cut name, bare first argument", "kube-controller", "kube-controller-manager\x00--profiling=false\x00", "kube-controller-manager"},
		{"short name is kept", "kubelet", "/usr/bin/kubelet\x00--config=/var/lib/kubelet/config.yaml\x00", "kubelet"},
		{"15 characters, not cut", "abcdefghijklmno", "/usr/bin/abcdefghijklmno\x00", "abcdefghijklmno"},
		{"rewritten title is not a name", "postgres-worker", "postgres: checkpointer\x00", "postgres-worker"},
		{"other first argument", "kube-controller", "/usr/bin/python3\x00/opt/kube-controller-manager.py\x00", "kube-controller"},
		{"kernel thread, empty cmdline", "ksoftirqd/0-abc", "", "ksoftirqd/0-abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, fullExecutableName(tt.status, []byte(tt.cmdline)))
		})
	}
}

// processInfo reports the full executable of a process whose status Name the
// kernel cut.
func TestLinuxProcManager_ProcessFullExecutable(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/proc/7/cmdline", []byte("/usr/local/bin/kube-controller-manager\x00--profiling=false\x00"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/proc/7/status", []byte("Name:\tkube-controller\nState:\tS (sleeping)\nPid:\t7\n"), 0o644))
	lpm := &LinuxProcManager{conn: &fakeProcConn{fs: fs}}

	p, err := lpm.Process(7)
	require.NoError(t, err)
	require.Equal(t, "kube-controller-manager", p.Executable)
	require.Equal(t, "/usr/local/bin/kube-controller-manager --profiling=false", p.Command)
}
