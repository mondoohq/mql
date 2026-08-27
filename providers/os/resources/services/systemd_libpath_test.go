// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Debian 11 and older and Ubuntu 18.04 and older have not completed the /usr
// merge: /lib is a real directory, every unit file lives in
// /lib/systemd/system, and /usr/lib/systemd/system is empty or absent. On
// ubuntu:16.04 that is all 108 service units.
//
// The search path left /lib/systemd/system out, so a filesystem scan of any of
// those hosts reported no units, no sockets and no timers at all -- and the
// filesystem manager is the only path a filesystem, image or snapshot scan
// ever takes.
func TestSystemdUnitSearchPath_CoversPreUsrMergeHosts(t *testing.T) {
	assert.Contains(t, systemdUnitSearchPath, "/lib/systemd/system")

	// /usr/lib still wins where both exist, matching systemd's own precedence
	usrLib := -1
	lib := -1
	for i, p := range systemdUnitSearchPath {
		switch p {
		case "/usr/lib/systemd/system":
			usrLib = i
		case "/lib/systemd/system":
			lib = i
		}
	}
	require.NotEqual(t, -1, usrLib)
	require.NotEqual(t, -1, lib)
	assert.Less(t, usrLib, lib, "/usr/lib must be searched before /lib")
}

func preUsrMergeFs(t *testing.T) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/ssh.service", []byte(`[Unit]
Description=OpenBSD Secure Shell server

[Service]
ExecStart=/usr/sbin/sshd -D
User=root
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
`), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/cron.service", []byte(`[Unit]
Description=Regular background program processing daemon

[Service]
ExecStart=/usr/sbin/cron -f
NoNewPrivileges=yes
`), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/dbus.socket", []byte(`[Unit]
Description=D-Bus System Message Bus Socket

[Socket]
ListenStream=/var/run/dbus/system_bus_socket
`), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/apt-daily.timer", []byte(`[Unit]
Description=Daily apt download activities

[Timer]
OnCalendar=*-*-* 6,18:00
`), 0o644))
	return fs
}

func TestSystemdFSManagers_ReadUnitsFromLib(t *testing.T) {
	fs := preUsrMergeFs(t)

	units, err := (&SystemdFSUnitManager{Fs: fs}).List()
	require.NoError(t, err)
	require.Len(t, units, 2)

	byName := map[string]*SystemdUnit{}
	for _, u := range units {
		byName[u.Name] = u
	}
	require.Contains(t, byName, "ssh.service")
	assert.Equal(t, "OpenBSD Secure Shell server", byName["ssh.service"].Description)
	assert.Equal(t, "/usr/sbin/sshd -D", byName["ssh.service"].ExecStart)
	assert.False(t, byName["ssh.service"].NoNewPrivileges)
	assert.True(t, byName["cron.service"].NoNewPrivileges)

	sockets, err := (&SystemdFSSocketManager{Fs: fs}).List()
	require.NoError(t, err)
	require.Len(t, sockets, 1)
	assert.Equal(t, "D-Bus System Message Bus Socket", sockets[0].Description)

	timers, err := (&SystemdFSTimerManager{Fs: fs}).List()
	require.NoError(t, err)
	require.Len(t, timers, 1)
	assert.Equal(t, "Daily apt download activities", timers[0].Description)
}

// A usr-merged host must not report the same unit twice just because /lib and
// /usr/lib both resolve to it.
func TestSystemdFSUnitManager_UsrMergedHostHasNoDuplicates(t *testing.T) {
	fs := afero.NewMemMapFs()
	unit := []byte("[Unit]\nDescription=Demo\n\n[Service]\nExecStart=/usr/bin/demo\n")
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service", unit, 0o644))
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/demo.service", unit, 0o644))

	units, err := (&SystemdFSUnitManager{Fs: fs}).List()
	require.NoError(t, err)
	require.Len(t, units, 1)
	assert.Equal(t, "/usr/lib/systemd/system/demo.service", units[0].FragmentPath)
}
