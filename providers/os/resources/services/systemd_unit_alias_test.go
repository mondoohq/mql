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

// `systemctl list-unit-files` names an alias as well as the unit it points at,
// and `systemctl show` answers for both with the same Id. Shape taken from a
// live NixOS 25.11 host, where nine units are aliased this way and the list
// came back with 117 entries for 108 distinct units.
func TestListViaSystemctlCollapsesAliases(t *testing.T) {
	unitFiles := strings.Join([]string{
		"dbus.service                   alias    -",
		"dbus-broker.service            enabled  enabled",
		"systemd-logind.service         static   -",
		"dbus-org.freedesktop.login1.service alias -",
		"sshd.service                   enabled  enabled",
		"",
	}, "\n")

	// Both dbus.service and dbus-broker.service report Id=dbus-broker.service;
	// both logind names report Id=systemd-logind.service.
	show := strings.Join([]string{
		"Id=dbus-broker.service",
		"Description=D-Bus System Message Bus",
		"LoadState=loaded",
		"ActiveState=active",
		"",
		"Id=dbus-broker.service",
		"Description=D-Bus System Message Bus",
		"LoadState=loaded",
		"ActiveState=active",
		"",
		"Id=systemd-logind.service",
		"Description=User Login Management",
		"LoadState=loaded",
		"ActiveState=active",
		"",
		"Id=systemd-logind.service",
		"Description=User Login Management",
		"LoadState=loaded",
		"ActiveState=active",
		"",
		"Id=sshd.service",
		"Description=SSH Daemon",
		"LoadState=loaded",
		"ActiveState=active",
		"",
	}, "\n")

	names := []string{
		"dbus.service", "dbus-broker.service", "systemd-logind.service",
		"dbus-org.freedesktop.login1.service", "sshd.service",
	}

	commands := map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {Stdout: unitFiles},
		buildSystemdUnitShowCommand(names):                           {Stdout: show},
	}

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "nixos", Family: []string{"linux"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)

	mgr := &SystemdUnitManager{conn: mockConn}
	units, err := mgr.List()
	require.NoError(t, err)

	byName := map[string]int{}
	for _, u := range units {
		byName[u.Name]++
	}
	for name, count := range byName {
		assert.Equal(t, 1, count, "unit %q reported %d times", name, count)
	}

	assert.Len(t, units, 3, "five unit-file names for three distinct units")
	assert.Contains(t, byName, "dbus-broker.service")
	assert.Contains(t, byName, "systemd-logind.service")
	assert.Contains(t, byName, "sshd.service")
	// The alias name is not a unit of its own, so it must not appear.
	assert.NotContains(t, byName, "dbus.service")
	assert.NotContains(t, byName, "dbus-org.freedesktop.login1.service")
}
