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

func serviceMock(t *testing.T, commands map[string]*mock.Command) *recordingConnection {
	t.Helper()
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"ubuntu", "linux"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &recordingConnection{Connection: mockConn}
}

// systemctl answers for an alias with the canonical unit's Id. Output taken
// from a live Ubuntu 16.04 host (systemd 229).
func TestParseServiceSystemDShowKeysAliases(t *testing.T) {
	services, err := ParseServiceSystemDShow(strings.NewReader(strings.Join([]string{
		"Id=ssh.service",
		"Names=ssh.service sshd.service",
		"Description=OpenBSD Secure Shell server",
		"LoadState=loaded",
		"ActiveState=active",
		"UnitFileState=enabled",
		"",
		"Id=rsyslog.service",
		"Names=syslog.service rsyslog.service",
		"Description=System Logging Service",
		"LoadState=loaded",
		"ActiveState=active",
		"UnitFileState=enabled",
		"",
	}, "\n")))
	require.NoError(t, err)

	require.Contains(t, services, "sshd")
	assert.Equal(t, "ssh", services["sshd"].Name)
	assert.True(t, services["sshd"].Running)
	assert.Same(t, services["ssh"], services["sshd"])

	// syslog is listed before the canonical name and must not displace it
	require.Contains(t, services, "syslog")
	assert.Equal(t, "rsyslog", services["rsyslog"].Name)
	assert.Equal(t, "rsyslog", services["syslog"].Name)
}

// systemd 229 and 237 report a masked unit with UnitFileState=bad. Output from
// live Ubuntu 16.04 and 18.04 hosts.
func TestParseServiceSystemDShowMaskedWithBadUnitFileState(t *testing.T) {
	services, err := ParseServiceSystemDShow(strings.NewReader(strings.Join([]string{
		"Id=g04-mask.service",
		"Names=g04-mask.service",
		"Description=g04-mask.service",
		"LoadState=masked",
		"ActiveState=inactive",
		"UnitFileState=bad",
		"",
	}, "\n")))
	require.NoError(t, err)
	require.Contains(t, services, "g04-mask")
	assert.True(t, services["g04-mask"].Installed)
	assert.True(t, services["g04-mask"].Masked)
	assert.False(t, services["g04-mask"].Enabled)
}

func TestSystemDServiceManagerGetByAlias(t *testing.T) {
	const showCmd = "systemctl show --property=Id,Names,LoadState,ActiveState,UnitFileState,Description sshd.service"
	conn := serviceMock(t, map[string]*mock.Command{
		showCmd: {Stdout: strings.Join([]string{
			"Id=ssh.service",
			"Names=ssh.service sshd.service",
			"Description=OpenBSD Secure Shell server",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=enabled",
			"",
		}, "\n")},
	})

	service, err := (&SystemDServiceManager{conn: conn}).Get("sshd")
	require.NoError(t, err)
	assert.Equal(t, &Service{
		Name:        "sshd",
		Description: "OpenBSD Secure Shell server",
		Installed:   true,
		Running:     true,
		Enabled:     true,
		Type:        "systemd",
	}, service)
}

// Shape of a live Ubuntu 24.04 host (systemd 255): list-unit-files reports the
// aliases as "alias", list-units reports only the canonical units.
func TestSystemDServiceManagerListResolvesAliasRows(t *testing.T) {
	const showCmd = "systemctl show --property=Id,Names,LoadState,ActiveState,UnitFileState,Description chrony-wait.service chronyd.service syslog.service"
	conn := serviceMock(t, map[string]*mock.Command{
		unitFilesCmd: {Stdout: strings.Join([]string{
			"UNIT FILE                                      STATE           PRESET",
			"chrony-dnssrv@.service                         static          -",
			"chrony-wait.service                            disabled        enabled",
			"chrony.service                                 enabled         enabled",
			"chronyd.service                                alias           -",
			"rsyslog.service                                enabled         enabled",
			"syslog.service                                 alias           -",
			"",
			"6 unit files listed.",
			"",
		}, "\n")},
		listUnitsCmd: {Stdout: strings.Join([]string{
			"  UNIT                                           LOAD      ACTIVE   SUB     DESCRIPTION",
			"  chrony.service                                 loaded    active   running chrony, an NTP client/server",
			"  rsyslog.service                                loaded    active   running System Logging Service",
			"",
		}, "\n")},
		showCmd: {Stdout: strings.Join([]string{
			"Id=chrony-wait.service",
			"Names=chrony-wait.service",
			"Description=Wait for chrony to synchronize system clock",
			"LoadState=loaded",
			"ActiveState=inactive",
			"UnitFileState=disabled",
			"",
			"Id=chrony.service",
			"Names=chrony.service chronyd.service",
			"Description=chrony, an NTP client/server",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=enabled",
			"",
			"Id=rsyslog.service",
			"Names=rsyslog.service syslog.service",
			"Description=System Logging Service",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=enabled",
			"",
		}, "\n")},
	})

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)
	assert.Equal(t, []string{unitFilesCmd, listUnitsCmd, showCmd}, conn.commands)

	byName := servicesByName(services)
	require.Len(t, byName, 6)

	assert.Equal(t, &Service{
		Name:        "chronyd",
		Description: "chrony, an NTP client/server",
		Installed:   true,
		Running:     true,
		Enabled:     true,
		Type:        "systemd",
	}, byName["chronyd"])
	assert.True(t, byName["syslog"].Running)
	assert.True(t, byName["syslog"].Enabled)

	// an unloaded unit keeps its own state and gains its description
	assert.False(t, byName["chrony-wait"].Running)
	assert.False(t, byName["chrony-wait"].Enabled)
	assert.Equal(t, "Wait for chrony to synchronize system clock", byName["chrony-wait"].Description)

	// the canonical units are untouched
	assert.True(t, byName["chrony"].Running)
	assert.True(t, byName["rsyslog"].Running)
	// the template is not shown and stays as listed
	assert.True(t, byName["chrony-dnssrv@"].Static)
	assert.False(t, byName["chrony-dnssrv@"].Running)
}

// On systemd 229 and 237 list-unit-files reports an alias with the state of
// the unit it points at, so it cannot be told apart from a real unit there.
// Shape of a live Ubuntu 16.04 host.
func TestSystemDServiceManagerListResolvesAliasRowsOldSystemd(t *testing.T) {
	const showCmd = "systemctl show --property=Id,Names,LoadState,ActiveState,UnitFileState,Description dbus-org.freedesktop.login1.service sshd.service"
	conn := serviceMock(t, map[string]*mock.Command{
		unitFilesCmd: {Stdout: strings.Join([]string{
			"UNIT FILE                                     STATE   ",
			"dbus-org.freedesktop.login1.service           static  ",
			"ssh.service                                   enabled ",
			"sshd.service                                  enabled ",
			"systemd-logind.service                        static  ",
			"",
			"4 unit files listed.",
			"",
		}, "\n")},
		listUnitsCmd: {Stdout: strings.Join([]string{
			"  UNIT                                                  LOAD      ACTIVE   SUB     DESCRIPTION",
			"  ssh.service                                           loaded    active   running OpenBSD Secure Shell server",
			"  systemd-logind.service                                loaded    active   running Login Service",
			"",
		}, "\n")},
		showCmd: {Stdout: strings.Join([]string{
			"Id=systemd-logind.service",
			"Names=dbus-org.freedesktop.login1.service systemd-logind.service",
			"Description=Login Service",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=static",
			"",
			"Id=ssh.service",
			"Names=ssh.service sshd.service",
			"Description=OpenBSD Secure Shell server",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=enabled",
			"",
		}, "\n")},
	})

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)

	byName := servicesByName(services)
	assert.True(t, byName["sshd"].Running)
	assert.Equal(t, "OpenBSD Secure Shell server", byName["sshd"].Description)
	assert.True(t, byName["dbus-org.freedesktop.login1"].Running)
	assert.True(t, byName["dbus-org.freedesktop.login1"].Static)
}

// A failed show leaves the rows as list-unit-files reported them.
func TestSystemDServiceManagerListKeepsAliasRowsWhenShowFails(t *testing.T) {
	conn := serviceMock(t, map[string]*mock.Command{
		unitFilesCmd: {Stdout: strings.Join([]string{
			"UNIT FILE        STATE   PRESET",
			"chrony.service   enabled enabled",
			"chronyd.service  alias   -",
			"",
		}, "\n")},
		listUnitsCmd: {Stdout: strings.Join([]string{
			"  UNIT            LOAD   ACTIVE SUB     DESCRIPTION",
			"  chrony.service  loaded active running chrony, an NTP client/server",
			"",
		}, "\n")},
	})

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)
	byName := servicesByName(services)
	require.Contains(t, byName, "chronyd")
	assert.True(t, byName["chronyd"].Installed)
	assert.False(t, byName["chronyd"].Running)
	assert.True(t, byName["chrony"].Running)
}
