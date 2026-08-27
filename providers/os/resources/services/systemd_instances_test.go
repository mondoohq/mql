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

const (
	unitFilesCmd = "systemctl list-unit-files --type service --all"
	listUnitsCmd = "systemctl list-units --type service --all"
)

// Shape taken from a live Debian 13 host: the template units carry the unit
// file, the running instances only ever appear in list-units.
func instanceMock(t *testing.T, extra map[string]*mock.Command) *recordingConnection {
	t.Helper()

	commands := map[string]*mock.Command{
		unitFilesCmd: {Stdout: strings.Join([]string{
			"UNIT FILE                 STATE     PRESET",
			"getty@.service            enabled   enabled",
			"nut-driver@.service       indirect  enabled",
			"ssh.service               enabled   enabled",
			"",
			"3 unit files listed.",
			"",
		}, "\n")},
		listUnitsCmd: {Stdout: strings.Join([]string{
			"  UNIT                     LOAD   ACTIVE SUB     DESCRIPTION",
			"  getty@tty1.service       loaded active running Getty on tty1",
			"  nut-driver@apc.service   loaded active running NUT device 'apc'",
			"  ssh.service              loaded active running OpenBSD Secure Shell server",
			"  firewalld.service        not-found inactive dead firewalld.service",
			"",
		}, "\n")},
	}
	for k, v := range extra {
		commands[k] = v
	}

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)

	return &recordingConnection{Connection: mockConn}
}

func servicesByName(services []*Service) map[string]*Service {
	byName := map[string]*Service{}
	for _, s := range services {
		byName[s.Name] = s
	}
	return byName
}

// A running instance of a template unit has to appear in the list. Before this,
// only the template (getty@, nut-driver@) was listed, with running=false, so a
// policy asking whether a getty is running got the wrong answer.
func TestSystemDServiceManagerListIncludesTemplateInstances(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description getty@tty1.service nut-driver@apc.service"

	conn := instanceMock(t, map[string]*mock.Command{
		showCmd: {Stdout: strings.Join([]string{
			"Id=getty@tty1.service",
			"Description=Getty on tty1",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=enabled",
			"",
			"Id=nut-driver@apc.service",
			"Description=NUT device 'apc'",
			"LoadState=loaded",
			"ActiveState=active",
			"UnitFileState=enabled",
			"",
		}, "\n")},
	})

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)

	byName := servicesByName(services)

	require.Contains(t, byName, "getty@tty1", "running template instance must be listed")
	assert.True(t, byName["getty@tty1"].Running)
	assert.True(t, byName["getty@tty1"].Enabled)

	require.Contains(t, byName, "nut-driver@apc")
	assert.True(t, byName["nut-driver@apc"].Running)
	// the instance is enabled even though its template reports "indirect",
	// so the state must come from the instance, not be inherited
	assert.True(t, byName["nut-driver@apc"].Enabled)
	assert.False(t, byName["nut-driver@"].Enabled)

	// the templates themselves stay, and stay not-running
	assert.False(t, byName["getty@"].Running)
	assert.False(t, byName["nut-driver@"].Running)

	// ordinary units are untouched
	assert.True(t, byName["ssh"].Running)
	assert.True(t, byName["ssh"].Enabled)

	// list-units --all also names units that do not exist on the host,
	// because something references them; they are not services here
	assert.NotContains(t, byName, "firewalld")
}

// A failed "systemctl show" costs the unit-file state, not the whole unit.
func TestSystemDServiceManagerListKeepsInstancesWhenShowFails(t *testing.T) {
	conn := instanceMock(t, nil) // no show command registered -> the call fails

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)

	byName := servicesByName(services)
	require.Contains(t, byName, "getty@tty1")
	assert.True(t, byName["getty@tty1"].Running)
	assert.True(t, byName["getty@tty1"].Installed)
}
