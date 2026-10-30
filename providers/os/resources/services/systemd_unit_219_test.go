// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// rhel7ShowPartial is what systemd 219 (RHEL 7.9) prints for
// `systemctl show --property=<systemdUnitShowProperties> -- chronyd.service sshd.service`:
// the properties it knows for the first unit, in its own order, and nothing for
// the second. It exits 1 with nothing on stderr, because ProtectKernelLogs,
// DynamicUser and the other newer settings are unknown to it.
const rhel7ShowPartial = `Type=forking
ExecStart={ path=/usr/sbin/chronyd ; argv[]=/usr/sbin/chronyd $OPTIONS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
UMask=0022
User=
Group=
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
NoNewPrivileges=no
Id=chronyd.service
Description=NTP client/server
LoadState=loaded
ActiveState=active
SubState=running
FragmentPath=/usr/lib/systemd/system/chronyd.service
UnitFileState=enabled
`

// rhel7ShowAllChronyd is an excerpt of `systemctl show --all -- chronyd.service`
// on the same host.
const rhel7ShowAllChronyd = `Type=forking
ExecStart={ path=/usr/sbin/chronyd ; argv[]=/usr/sbin/chronyd $OPTIONS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
NoNewPrivileges=no
Id=chronyd.service
Names=chronyd.service
Description=NTP client/server
LoadState=loaded
ActiveState=active
SubState=running
FragmentPath=/usr/lib/systemd/system/chronyd.service
UnitFileState=enabled
`

const rhel7ShowAllSshd = `Type=notify
ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=
NoNewPrivileges=no
Id=sshd.service
Names=sshd.service
Description=OpenSSH server daemon
LoadState=loaded
ActiveState=active
SubState=running
FragmentPath=/usr/lib/systemd/system/sshd.service
UnitFileState=enabled
`

// systemd.units on RHEL 7 read every unit from the unit files, with no runtime
// state, because the batch exited 1. Without the --all retry this list comes
// from the unit-file fallback and ActiveState is empty.
func TestSystemdUnitManager_ListRetriesWithAllPropertiesOnSystemd219(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {
			Stdout: "chronyd.service  enabled\nsshd.service     enabled\n",
		},
		buildSystemdUnitShowCommand([]string{"chronyd.service", "sshd.service"}): {
			Stdout:     rhel7ShowPartial,
			ExitStatus: 1,
		},
		buildSystemdUnitShowAllCommand([]string{"chronyd.service", "sshd.service"}): {
			Stdout: rhel7ShowAllChronyd + "\n" + rhel7ShowAllSshd,
		},
	})

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	require.Len(t, units, 2)

	assert.Equal(t, "chronyd.service", units[0].Name)
	assert.Equal(t, "active", units[0].ActiveState)
	assert.Equal(t, "running", units[0].SubState)
	assert.Equal(t, "enabled", units[0].UnitFileState)
	assert.True(t, units[0].PrivateTmp)

	assert.Equal(t, "sshd.service", units[1].Name)
	assert.Equal(t, "active", units[1].ActiveState)
	assert.Equal(t, "/usr/sbin/sshd -D $OPTIONS", units[1].ExecStart)
}

// systemd.unit("chronyd") on RHEL 7 read installed=false: the single-unit show
// exited 1, and the unit-file fallback looked for a file named "chronyd".
func TestSystemdUnitManager_GetRetriesWithAllPropertiesOnSystemd219(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		buildSystemdUnitShowCommand([]string{"chronyd"}): {
			Stdout:     rhel7ShowPartial,
			ExitStatus: 1,
		},
		buildSystemdUnitShowAllCommand([]string{"chronyd"}): {
			Stdout: rhel7ShowAllChronyd,
		},
	})

	unit, err := (&SystemdUnitManager{conn: conn}).Get("chronyd")
	require.NoError(t, err)
	assert.True(t, unit.Installed)
	assert.Equal(t, "chronyd.service", unit.Name)
	assert.Equal(t, "active", unit.ActiveState)
	assert.Equal(t, "enabled", unit.UnitFileState)
}

// A systemctl that prints no unit at all is not answering, so it is not asked
// again; the unit files are read instead. The mock answers the --all command
// with an empty listing, so asking it would make Get report not found.
func TestSystemdUnitManager_GetDoesNotRetryWithoutAnyRecord(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		buildSystemdUnitShowCommand([]string{"sshd.service"}): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
		buildSystemdUnitShowAllCommand([]string{"sshd.service"}): {
			Stdout: "Id=sshd.service\nLoadState=not-found\n",
		},
	})

	unit, err := (&SystemdUnitManager{conn: conn}).Get("sshd.service")
	require.NoError(t, err)
	assert.Equal(t, "/usr/sbin/sshd -D", unit.ExecStart)
}

// The unit-file fallback completes a bare name to a service the way systemctl
// does, so systemd.unit("chronyd") finds chronyd.service on disk.
func TestSystemdFSUnitManager_GetCompletesServiceSuffix(t *testing.T) {
	conn := unitFallbackConn(t, nil)

	unit, err := (&SystemdFSUnitManager{Fs: conn.FileSystem()}).Get("chronyd")
	require.NoError(t, err)
	assert.Equal(t, "chronyd.service", unit.Name)
	assert.Equal(t, "/usr/sbin/chronyd", unit.ExecStart)
}

func TestWithSystemdUnitType(t *testing.T) {
	assert.Equal(t, "chronyd.service", withSystemdUnitType("chronyd"))
	assert.Equal(t, "chronyd.service", withSystemdUnitType("chronyd.service"))
	assert.Equal(t, "sshd.socket", withSystemdUnitType("sshd.socket"))
	assert.Equal(t, "fstrim.timer", withSystemdUnitType("fstrim.timer"))
	// a dot in the name is not a unit type
	assert.Equal(t, "dbus-org.freedesktop.login1.service", withSystemdUnitType("dbus-org.freedesktop.login1"))
}
