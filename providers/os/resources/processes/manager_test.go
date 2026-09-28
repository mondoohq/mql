// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

func TestManagerDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"linux", "unix"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 3, len(mounts))
}

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 41, len(mounts))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "freebsd"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 41, len(mounts))
}

func TestManagerFreeBSD15State(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/freebsd15.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	list, err := mm.List()
	require.NoError(t, err)
	require.Len(t, list, 56)

	byPid := map[int64]*processes.OSProcess{}
	for _, p := range list {
		byPid[p.Pid] = p
	}
	want := map[int64]string{
		0:     "D (disk sleep)",       // DLs [kernel]
		1:     "I (idle)",             // ILs /sbin/init
		2:     "W (interrupt thread)", // WL [clock]
		11:    "R (running)",          // RNL [idle]
		1198:  "S (sleeping)",         // SCs syslogd
		1470:  "I (idle)",             // Is+ getty
		43851: "R (running)",          // R ps
	}
	for pid, state := range want {
		require.Contains(t, byPid, pid)
		assert.Equal(t, state, byPid[pid].State, "pid %d", pid)
	}
	assert.Equal(t, "/bin/sh - /dev/stdin daily", byPid[43822].Command)
}

// FreeBSD daemons rewrite their process title with setproctitle(3), so the
// first word of ps's command column is not the binary ("nginx:", "sshd:",
// "(postgres)"). The executable must come from ps's comm column, which holds
// the name of the binary that was exec'd, like Linux's /proc/<pid>/status Name.
func TestManagerFreeBSD14Executable(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/freebsd14.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	list, err := mm.List()
	require.NoError(t, err)
	require.Len(t, list, 57)

	byPid := map[int64]*processes.OSProcess{}
	for _, p := range list {
		byPid[p.Pid] = p
	}
	want := map[int64]string{
		0:     "kernel",       // [kernel]
		1:     "init",         // /sbin/init
		14:    "sequencer 00", // [sequencer 00], comm with a space
		355:   "dhclient",     // dhclient: system.syslog (dhclient)
		1830:  "sshd",         // sshd: /usr/sbin/sshd [listener] ...
		7894:  "nginx",        // nginx: master process /usr/local/sbin/nginx
		7895:  "nginx",        // nginx: worker process (nginx)
		29115: "mysqld",       // /usr/local/libexec/mysqld --basedir=...
		38854: "postgres",     // (postgres)
		38855: "postgres",     // postgres: background writer  (postgres)
		43271: "sshd-session", // sshd-session: ec2-user [priv] (sshd-session)
		43277: "sh",           // /bin/sh - /dev/stdin daily
		// exited before the comm listing ran: falls back to the command
		43280: "ps",
	}
	for pid, exe := range want {
		require.Contains(t, byPid, pid)
		assert.Equal(t, exe, byPid[pid].Executable, "pid %d", pid)
	}
	assert.Equal(t, "nginx: master process /usr/local/sbin/nginx", byPid[7894].Command)
	assert.Equal(t, "I (idle)", byPid[7894].State)
}

func TestManagerMacosStateUnset(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	list, err := mm.List()
	require.NoError(t, err)
	require.NotEmpty(t, list)
	for _, p := range list {
		assert.Empty(t, p.State, "pid %d", p.Pid)
		// the executable is still taken from the command; no comm lookup
		if p.Pid == 126 {
			assert.Equal(t, "UserEventAgent", p.Executable)
		}
	}
}

// func TestManagerWindows(t *testing.T) {
//  mock, err := mock.New(0, nil, mock.WithPath("./testdata/windows.toml"))
// 	require.NoError(t, err)
// 	m, err := motor.New(mock)
// 	require.NoError(t, err)

// 	mm, err := processes.ResolveManager(m)
// 	require.NoError(t, err)
// 	mounts, err := mm.List()
// 	require.NoError(t, err)

// 	assert.Equal(t, 5, len(mounts))
// }
