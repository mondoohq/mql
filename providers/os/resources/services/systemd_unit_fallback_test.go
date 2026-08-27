// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// unitFileListing is what `systemctl list-unit-files` prints. It keeps working
// when systemd is not running, because it only reads the unit files off disk.
const unitFileListing = `sshd.service     enabled  enabled
chronyd.service  enabled  enabled
`

// bootedElsewhere is what systemctl prints on stderr, exiting non-zero, when it
// cannot reach the bus -- in a container, a chroot, a rescue boot, or on a host
// running another init.
const bootedElsewhere = "System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n"

// fsConn is a mock connection whose filesystem is one we control, so the
// unit-file fallback has something to read.
type fsConn struct {
	shared.Connection
	fs afero.Fs
}

func (c *fsConn) FileSystem() afero.Fs { return c.fs }

func unitFallbackConn(t *testing.T, cmds map[string]*mock.Command) shared.Connection {
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
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/sshd.service", []byte(`[Unit]
Description=OpenSSH server daemon

[Service]
Type=notify
ExecStart=/usr/sbin/sshd -D
User=root
NoNewPrivileges=no
`), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/chronyd.service", []byte(`[Unit]
Description=NTP client/server

[Service]
Type=forking
ExecStart=/usr/sbin/chronyd
User=chrony
NoNewPrivileges=yes
ProtectSystem=full
`), 0o644))

	return &fsConn{Connection: conn, fs: fs}
}

// systemctl can name the units without a running systemd, but cannot report
// their properties: `systemctl show` exits non-zero with nothing on stdout.
// That parses into zero records, so before the fix systemd.units reported an
// empty list -- a host with no services at all -- and an assertion like
// `systemd.units.where(noNewPrivileges == false)` passed without a unit ever
// having been read.
func TestSystemdUnitManager_FallsBackToUnitFilesWhenShowCannotRun(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {
			Stdout: unitFileListing,
		},
		buildSystemdUnitShowCommand([]string{"sshd.service", "chronyd.service"}): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	require.Len(t, units, 2)

	byName := map[string]*SystemdUnit{}
	for _, u := range units {
		byName[u.Name] = u
	}

	require.Contains(t, byName, "sshd.service")
	assert.Equal(t, "OpenSSH server daemon", byName["sshd.service"].Description)
	assert.Equal(t, "/usr/sbin/sshd -D", byName["sshd.service"].ExecStart)
	assert.False(t, byName["sshd.service"].NoNewPrivileges)

	require.Contains(t, byName, "chronyd.service")
	assert.True(t, byName["chronyd.service"].NoNewPrivileges)
	assert.Equal(t, "full", byName["chronyd.service"].ProtectSystem)
}

// The same for a host where systemctl cannot even list the unit files.
func TestSystemdUnitManager_FallsBackWhenListCannotRun(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	assert.Len(t, units, 2)
}

// A single unit lookup degrades the same way, so service("sshd.service") does
// not report a unit that is sitting on disk as not found.
func TestSystemdUnitManager_GetFallsBackWhenShowCannotRun(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		buildSystemdUnitShowCommand([]string{"sshd.service"}): {
			Stderr:     bootedElsewhere,
			ExitStatus: 1,
		},
	})

	unit, err := (&SystemdUnitManager{conn: conn}).Get("sshd.service")
	require.NoError(t, err)
	assert.Equal(t, "sshd.service", unit.Name)
	assert.Equal(t, "/usr/sbin/sshd -D", unit.ExecStart)
}

// When systemctl answers, its values win -- they are the ones in effect after
// drop-ins have been merged, which the unit file on its own does not show.
func TestSystemdUnitManager_PrefersSystemctlWhenItAnswers(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {
			Stdout: unitFileListing,
		},
		buildSystemdUnitShowCommand([]string{"sshd.service", "chronyd.service"}): {
			Stdout: `Id=sshd.service
Description=OpenSSH server daemon
LoadState=loaded
ActiveState=active
NoNewPrivileges=yes

Id=chronyd.service
Description=NTP client/server
LoadState=loaded
ActiveState=active
NoNewPrivileges=yes
`,
		},
	})

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	require.Len(t, units, 2)

	// the drop-in merged value from systemctl, not the "no" in the unit file
	assert.Equal(t, "sshd.service", units[0].Name)
	assert.True(t, units[0].NoNewPrivileges)
	assert.Equal(t, "active", units[0].ActiveState)
}

// A host that really runs no service units still reports an empty list rather
// than an error.
func TestSystemdUnitManager_NoUnitsAtAll(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "almalinux", Version: "9.8", Family: []string{"redhat", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {Stdout: ""},
	}}))
	require.NoError(t, err)

	units, err := (&SystemdUnitManager{conn: &fsConn{Connection: conn, fs: afero.NewMemMapFs()}}).List()
	require.NoError(t, err)
	assert.Empty(t, units)
}
