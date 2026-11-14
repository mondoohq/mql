// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"errors"
	"testing"

	"bytes"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// /proc/self/status lines of the scanner, captured on RHEL 9 as ec2-user
// (uid 1000, member of adm and systemd-journal) and as root.
const (
	statusUser = "Name:\tcat\nUmask:\t0022\nState:\tR (running)\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t4 190 1000 \nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
	statusRoot = "Name:\tcat\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0 \nCapEff:\t000001ffffffffff\n"
	// a non-root scanner granted CAP_SYS_PTRACE (bit 19)
	statusUserPtrace = "Name:\tcat\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 \nCapEff:\t0000000000080000\n"

	// /proc/self/mounts lines from Debian 11 (kernel 5.10 names the mode) and
	// an older kernel that prints the number.
	mountsInvisible = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0\n"
	mountsHidepid2  = "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0\n"
	mountsGid4      = "proc /proc proc rw,nosuid,nodev,noexec,relatime,gid=4,hidepid=2 0 0\n"
	mountsNoaccess  = "proc /proc proc rw,relatime,hidepid=noaccess 0 0\n"
	mountsPtrace    = "proc /proc proc rw,relatime,hidepid=ptraceable 0 0\n"
	mountsPlain     = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
	mountsOff       = "proc /proc proc rw,relatime,hidepid=off 0 0\n"
)

func TestProcVisibility(t *testing.T) {
	tests := []struct {
		name   string
		mounts string
		status string
		hidden string // expected hidepid mode, "" when every process is visible
	}{
		{"invisible, non-root", mountsInvisible, statusUser, "invisible"},
		{"hidepid=2, non-root", mountsHidepid2, statusUser, "2"},
		{"noaccess, non-root", mountsNoaccess, statusUser, "noaccess"},
		{"ptraceable, non-root", mountsPtrace, statusUser, "ptraceable"},
		{"invisible, root", mountsInvisible, statusRoot, ""},
		{"hidepid=2, CAP_SYS_PTRACE", mountsHidepid2, statusUserPtrace, ""},
		{"gid=4 exempts a member of group 4", mountsGid4, statusUser, ""},
		{"gid=4 does not exempt a non-member", mountsGid4, "Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nGroups:\t1001 \nCapEff:\t0000000000000000\n", "2"},
		// without gid= the exempt group is root's group 0
		{"no gid=, member of group 0", mountsHidepid2, "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t0 1000 \nCapEff:\t0000000000000000\n", ""},
		// ptraceable has no group exemption in the kernel
		{"ptraceable ignores gid=", "proc /proc proc rw,gid=4,hidepid=ptraceable 0 0\n", statusUser, "ptraceable"},
		{"no hidepid", mountsPlain, statusUser, ""},
		{"hidepid=off", mountsOff, statusUser, ""},
		{"hidepid=0", "proc /proc proc rw,hidepid=0 0 0\n", statusUser, ""},
		// the last /proc mount is the one in effect
		{"remounted without hidepid", mountsHidepid2 + mountsPlain, statusUser, ""},
		{"remounted with hidepid", mountsPlain + mountsInvisible, statusUser, "invisible"},
		// an unreadable identity cannot be judged
		{"no status", mountsInvisible, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := procVisibility(tc.mounts + tc.status)
			if tc.hidden == "" {
				assert.NoError(t, err)
				return
			}
			var hidden *HiddenProcessesError
			require.True(t, errors.As(err, &hidden), "expected a HiddenProcessesError, got %v", err)
			assert.Equal(t, tc.hidden, hidden.Mode)
		})
	}
}

func TestHiddenProcessesErrorNamesUid(t *testing.T) {
	err := procVisibility(mountsInvisible + statusUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hidepid=invisible")
	assert.Contains(t, err.Error(), "uid 1000")
}

// A non-root scan under hidepid sees only its own pids in /proc. List must
// refuse instead of returning that subset, and Process must not report a
// hidden pid as nonexistent.
func newHiddenLinuxProcManager(t *testing.T, mounts, status string) *LinuxProcManager {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/proc", 0o755))
	writeProcEntry(t, fs, "4242", "bash")
	require.NoError(t, afero.WriteFile(fs, "/proc/self/mounts", []byte(mounts), 0o444))
	require.NoError(t, afero.WriteFile(fs, "/proc/self/status", []byte(status), 0o444))
	return &LinuxProcManager{conn: &fakeProcConn{fs: fs}}
}

func TestLinuxProcManager_HiddenListRefuses(t *testing.T) {
	lpm := newHiddenLinuxProcManager(t, mountsInvisible, statusUser)
	procs, err := lpm.List()
	var hidden *HiddenProcessesError
	require.True(t, errors.As(err, &hidden), "got %v", err)
	assert.Nil(t, procs)
}

func TestLinuxProcManager_HiddenPidIsNotMissing(t *testing.T) {
	lpm := newHiddenLinuxProcManager(t, mountsInvisible, statusUser)

	_, err := lpm.Process(1)
	var hidden *HiddenProcessesError
	require.True(t, errors.As(err, &hidden), "got %v", err)

	exists, err := lpm.Exists(1)
	assert.False(t, exists)
	require.True(t, errors.As(err, &hidden), "got %v", err)

	// the scanner's own process stays readable
	proc, err := lpm.Process(4242)
	require.NoError(t, err)
	assert.Equal(t, "bash", proc.Command)
}

func TestLinuxProcManager_RootUnderHidepidLists(t *testing.T) {
	lpm := newHiddenLinuxProcManager(t, mountsInvisible, statusRoot)
	procs, err := lpm.List()
	require.NoError(t, err)
	assert.Len(t, procs, 1)

	_, err = lpm.Process(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

// scriptedConn answers RunCommand from a table, like an SSH target.
type scriptedConn struct {
	fakeProcConn
	out map[string]string
}

func (c *scriptedConn) RunCommand(cmd string) (*shared.Command, error) {
	out, ok := c.out[cmd]
	if !ok {
		return &shared.Command{Command: cmd, ExitStatus: 1, Stdout: bytes.NewBufferString(""), Stderr: bytes.NewBufferString("not found")}, nil
	}
	return &shared.Command{Command: cmd, Stdout: bytes.NewBufferString(out), Stderr: bytes.NewBufferString("")}, nil
}

// Over SSH the process list comes from ps, which hidepid restricts the same
// way: as a non-root login, ps on Debian 11 printed only the user's own
// processes.
func TestUnixProcessManager_LinuxHidden(t *testing.T) {
	ps := "  PID %CPU %MEM    VSZ   RSS TT       STAT STIME     TIME   UID COMMAND\n" +
		"24297  0.0  0.4  15216  8992 ?        Ss   19:01 00:00:00  1000 /lib/systemd/systemd --user\n"
	platform := &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}}

	conn := &scriptedConn{out: map[string]string{
		"cat /proc/self/mounts /proc/self/status":                      mountsInvisible + statusUser,
		"ps axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command": ps,
	}}
	upm := &UnixProcessManager{conn: conn, platform: platform}
	_, err := upm.List()
	var hidden *HiddenProcessesError
	require.True(t, errors.As(err, &hidden), "got %v", err)

	_, err = upm.Process(1)
	require.True(t, errors.As(err, &hidden), "got %v", err)

	// the login's own process is still readable
	own, err := upm.Process(24297)
	require.NoError(t, err)
	assert.Equal(t, "/lib/systemd/systemd --user", own.Command)

	// with sudo the same cat reports root, and ps lists everything
	conn.out["cat /proc/self/mounts /proc/self/status"] = mountsInvisible + statusRoot
	upm = &UnixProcessManager{conn: conn, platform: platform}
	procs, err := upm.List()
	require.NoError(t, err)
	assert.Len(t, procs, 1)
}
