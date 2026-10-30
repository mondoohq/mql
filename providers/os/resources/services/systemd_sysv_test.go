// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func sysvTestConn(t *testing.T, commands map[string]*mock.Command) *recordingConnection {
	t.Helper()
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "redhat", Version: "7.9", Family: []string{"redhat", "linux"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &recordingConnection{Connection: mockConn}
}

// rhel7SysVShow is `systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description g04sysv.service`
// on RHEL 7.9 (systemd 219) for an init script in /etc/rc.d/init.d.
const rhel7SysVShow = `Id=g04sysv.service
Description=SYSV: g04 sysv service
LoadState=loaded
ActiveState=active
UnitFileState=bad
`

// is-enabled hands a SysV service to chkconfig; the notice goes to stderr.
const rhel7SysVRedirect = "g04sysv.service is not a native service, redirecting to /sbin/chkconfig.\nExecuting /sbin/chkconfig g04sysv --level=5\n"

func TestSystemdSysVServiceEnabledFromIsEnabled(t *testing.T) {
	services, err := ParseServiceSystemDShow(strings.NewReader(rhel7SysVShow))
	require.NoError(t, err)
	require.Contains(t, services, "g04sysv")
	svc := services["g04sysv"]
	require.True(t, svc.Installed)
	assert.True(t, svc.needsIsEnabled)

	conn := sysvTestConn(t, map[string]*mock.Command{
		"systemctl is-enabled -- g04sysv.service": {Stdout: "enabled\n", Stderr: rhel7SysVRedirect},
	})
	(&SystemDServiceManager{conn: conn}).resolveWithIsEnabled([]*Service{svc})

	assert.True(t, svc.Enabled)
	assert.False(t, svc.Masked)
	assert.False(t, svc.needsIsEnabled)
}

// chkconfig off: is-enabled prints disabled and exits 1. The answer still
// counts, and the unit is not asked about twice.
func TestSystemdSysVServiceDisabledFromIsEnabled(t *testing.T) {
	svc := &Service{Name: "g04sysv", Installed: true}
	applySystemdUnitFileState(svc, "bad")

	conn := sysvTestConn(t, map[string]*mock.Command{
		"systemctl is-enabled -- g04sysv.service": {Stdout: "disabled\n", Stderr: rhel7SysVRedirect, ExitStatus: 1},
	})
	mgr := &SystemDServiceManager{conn: conn}
	mgr.resolveWithIsEnabled([]*Service{svc, svc})

	assert.False(t, svc.Enabled)
	assert.False(t, svc.needsIsEnabled)
	assert.Len(t, conn.commands, 1)
}

// A unit whose state show reported is not asked about.
func TestSystemdResolveBadUnitFileStatesSkipsKnownStates(t *testing.T) {
	svc := &Service{Name: "chronyd", Installed: true}
	applySystemdUnitFileState(svc, "enabled")

	conn := sysvTestConn(t, nil)
	(&SystemDServiceManager{conn: conn}).resolveWithIsEnabled([]*Service{svc})

	assert.True(t, svc.Enabled)
	assert.Empty(t, conn.commands)
}

// debian12SysVShow is `systemctl show` on Debian 12 (systemd 252) for an
// LSB init script in /etc/init.d enabled with update-rc.d. Debian 9 (232) to
// 13 (257) print the same UnitFileState.
const debian12SysVShow = `Id=g04sysvon.service
Description=LSB: g04 sysv service (on)
LoadState=loaded
ActiveState=active
UnitFileState=generated
`

// is-enabled hands a Debian SysV service to systemd-sysv-install.
const debianSysVRedirect = "g04sysvon.service is not a native service, redirecting to systemd-sysv-install.\nExecuting: /lib/systemd/systemd-sysv-install is-enabled g04sysvon\n"

func TestSystemdDebianSysVServiceEnabledFromIsEnabled(t *testing.T) {
	services, err := ParseServiceSystemDShow(strings.NewReader(debian12SysVShow))
	require.NoError(t, err)
	require.Contains(t, services, "g04sysvon")
	svc := services["g04sysvon"]
	assert.False(t, svc.Enabled)
	assert.True(t, svc.needsIsEnabled)

	conn := sysvTestConn(t, map[string]*mock.Command{
		"systemctl is-enabled -- g04sysvon.service": {Stdout: "enabled\n", Stderr: debianSysVRedirect},
	})
	(&SystemDServiceManager{conn: conn}).resolveWithIsEnabled([]*Service{svc})

	assert.True(t, svc.Enabled)
	assert.False(t, svc.needsIsEnabled)
}

func TestParseSystemdIsEnabled(t *testing.T) {
	assert.Equal(t, "enabled", parseSystemdIsEnabled(strings.NewReader("enabled\n")))
	assert.Equal(t, "disabled", parseSystemdIsEnabled(strings.NewReader("disabled\n")))
	assert.Equal(t, "masked", parseSystemdIsEnabled(strings.NewReader("masked\n")))
	// no answer at all, or something that is not a state
	assert.Equal(t, "", parseSystemdIsEnabled(strings.NewReader("")))
	assert.Equal(t, "", parseSystemdIsEnabled(strings.NewReader("Failed to get unit file state for x.service: No such file or directory\n")))
}
