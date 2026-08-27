// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

// unitFileList is what `systemctl list-unit-files` prints. It reads the unit
// files off disk, so it keeps working with no systemd running -- unlike
// `list-units` and `show`, which need the bus.
const (
	timerUnitFileList = `UNIT FILE            STATE    PRESET
dnf-makecache.timer  enabled  enabled

1 unit files listed.
`
	socketUnitFileList = `UNIT FILE    STATE    PRESET
dbus.socket  enabled  enabled

1 unit files listed.
`
)

func systemdFallbackConn(t *testing.T, cmds map[string]*mock.Command) shared.Connection {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "almalinux",
			Version: "9.8",
			Family:  []string{"redhat", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{Commands: cmds}))
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/dnf-makecache.timer", []byte(`[Unit]
Description=dnf makecache --timer

[Timer]
OnBootSec=10min
OnUnitInactiveSec=1h
Unit=dnf-makecache.service

[Install]
WantedBy=timers.target
`), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/dbus.socket", []byte(`[Unit]
Description=D-Bus System Message Bus Socket

[Socket]
ListenStream=/run/dbus/system_bus_socket

[Install]
WantedBy=sockets.target
`), 0o644))

	return &fsConn{Connection: conn, fs: fs}
}

// `systemctl list-unit-files` names the timers without a running systemd, but
// `list-units` needs the bus and exits non-zero with nothing on stdout. That
// parses into "no running state", so the merge left every timer with a blank
// description, and `systemctl show` failing the same way left onCalendar blank
// too. dnf-makecache.timer reported description "" against a unit file that
// says "dnf makecache --timer".
func TestSystemdTimerManager_FallsBackToUnitFilesWhenListUnitsCannotRun(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type timer --all": {Stdout: timerUnitFileList},
		"systemctl list-units --type timer --all": {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	timers, err := NewSystemdTimerManager(conn).List()
	require.NoError(t, err)
	require.Len(t, timers, 1)

	assert.Equal(t, "dnf-makecache", timers[0].Name)
	assert.Equal(t, "dnf makecache --timer", timers[0].Description)
	assert.True(t, timers[0].Installed)
}

func TestSystemdTimerManager_ShowPropertiesFallsBack(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		buildShowPropertyCommand("Unit,OnCalendar,Persistent", "dnf-makecache.timer"): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	props, err := NewSystemdTimerManager(conn).ShowTimerProperties("dnf-makecache")
	require.NoError(t, err)
	assert.Equal(t, "dnf-makecache.service", props["Unit"])
}

func TestSystemdSocketManager_FallsBackToUnitFilesWhenListUnitsCannotRun(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type socket --all": {Stdout: socketUnitFileList},
		"systemctl list-units --type socket --all": {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	sockets, err := NewSystemdSocketManager(conn).List()
	require.NoError(t, err)
	require.Len(t, sockets, 1)

	assert.Equal(t, "dbus", sockets[0].Name)
	assert.Equal(t, "D-Bus System Message Bus Socket", sockets[0].Description)
}

// The listen addresses are what an exposure audit reads, and they came back
// empty on every host systemctl could not answer for.
func TestSystemdSocketManager_ShowPropertiesFallsBack(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		buildShowPropertyCommand("Triggers,Accept,Listen", "dbus.socket"): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	props, err := NewSystemdSocketManager(conn).ShowSocketProperties("dbus")
	require.NoError(t, err)
	assert.Contains(t, props["Listen"], "/run/dbus/system_bus_socket")
}

// A single lookup does not report a timer sitting on disk as not found.
func TestSystemdTimerManager_GetFallsBack(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		buildSystemdShowCommand([]string{"dnf-makecache.timer"}): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	timer, err := NewSystemdTimerManager(conn).Get("dnf-makecache")
	require.NoError(t, err)
	assert.Equal(t, "dnf-makecache", timer.Name)
	assert.Equal(t, "dnf makecache --timer", timer.Description)
}

func TestSystemdSocketManager_GetFallsBack(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		buildSystemdShowCommand([]string{"dbus.socket"}): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	socket, err := NewSystemdSocketManager(conn).Get("dbus")
	require.NoError(t, err)
	assert.Equal(t, "dbus", socket.Name)
	assert.Equal(t, "D-Bus System Message Bus Socket", socket.Description)
}

// When systemctl answers, its values still win.
func TestSystemdTimerManager_PrefersSystemctlWhenItAnswers(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type timer --all": {Stdout: timerUnitFileList},
		"systemctl list-units --type timer --all": {Stdout: `UNIT                 LOAD   ACTIVE SUB     DESCRIPTION
dnf-makecache.timer  loaded active waiting dnf makecache --timer

1 loaded units listed.
`},
	})

	timers, err := NewSystemdTimerManager(conn).List()
	require.NoError(t, err)
	require.Len(t, timers, 1)
	assert.True(t, timers[0].Running)
}
