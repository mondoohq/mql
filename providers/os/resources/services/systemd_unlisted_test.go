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

// Amazon Linux 2023 (systemd 252): list-unit-files names the templates
// g04-ttpl@.timer and refresh-policy-routes@.timer; only list-units names
// their running instances.
func TestSystemdTimerManagerListAddsTemplateInstances(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Family: []string{"linux"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"systemctl list-unit-files --type timer --all": {
				Stdout: strings.Join([]string{
					"UNIT FILE                      STATE    PRESET",
					"fstrim.timer                   enabled  enabled",
					"g04-ttpl@.timer                indirect disabled",
					"refresh-policy-routes@.timer   static   -",
					"",
					"3 unit files listed.",
					"",
				}, "\n"),
			},
			"systemctl list-units --type timer --all": {
				Stdout: strings.Join([]string{
					"  UNIT                             LOAD   ACTIVE   SUB     DESCRIPTION",
					"  fstrim.timer                     loaded active   waiting Discard unused blocks once a week",
					"  g04-ttpl@x.timer                 loaded active   waiting g04 templated timer x",
					"  refresh-policy-routes@ens5.timer loaded active   waiting refresh-policy-routes@ens5.timer",
					"",
					"LOAD   = Reflects whether the unit definition was properly loaded.",
					"3 loaded units listed.",
					"",
				}, "\n"),
			},
			"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description g04-ttpl@x.timer refresh-policy-routes@ens5.timer": {
				Stdout: strings.Join([]string{
					"Id=g04-ttpl@x.timer",
					"Description=g04 templated timer x",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
					"Id=refresh-policy-routes@ens5.timer",
					"Description=refresh-policy-routes@ens5.timer",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=static",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	timers, err := (&SystemdTimerManager{conn: mockConn}).List()
	require.NoError(t, err)
	byName := map[string]*SystemdTimer{}
	for _, timer := range timers {
		byName[timer.Name] = timer
	}
	require.Len(t, byName, 5)

	x := byName["g04-ttpl@x"]
	require.NotNil(t, x)
	assert.True(t, x.Installed)
	assert.True(t, x.Enabled)
	assert.True(t, x.Running)
	assert.False(t, x.Static)
	assert.Equal(t, "g04 templated timer x", x.Description)

	ens5 := byName["refresh-policy-routes@ens5"]
	require.NotNil(t, ens5)
	assert.True(t, ens5.Static)
	assert.False(t, ens5.Enabled)
	assert.True(t, ens5.Running)

	// the templates stay as list-unit-files reports them
	require.NotNil(t, byName["g04-ttpl@"])
	assert.False(t, byName["g04-ttpl@"].Running)
}

func TestSystemdSocketManagerListAddsTemplateInstances(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Family: []string{"linux"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"systemctl list-unit-files --type socket --all": {
				Stdout: strings.Join([]string{
					"UNIT FILE                        STATE    PRESET",
					"g04-sk@.socket                   indirect disabled",
					"g04.socket                       enabled  disabled",
					"systemd-journald@.socket         static   -",
					"",
					"3 unit files listed.",
					"",
				}, "\n"),
			},
			"systemctl list-units --type socket --all": {
				Stdout: strings.Join([]string{
					"  UNIT                            LOAD   ACTIVE   SUB       DESCRIPTION",
					"  g04-sk@a.socket                 loaded active   listening g04 templated socket a",
					"  g04.socket                      loaded active   listening g04 socket",
					"  gone@b.socket                   not-found inactive dead   gone@b.socket",
					"",
					"LOAD   = Reflects whether the unit definition was properly loaded.",
					"3 loaded units listed.",
					"",
				}, "\n"),
			},
			"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description g04-sk@a.socket": {
				Stdout: strings.Join([]string{
					"Id=g04-sk@a.socket",
					"Description=g04 templated socket a",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	sockets, err := (&SystemdSocketManager{conn: mockConn}).List()
	require.NoError(t, err)
	byName := map[string]*SystemdSocket{}
	for _, socket := range sockets {
		byName[socket.Name] = socket
	}
	require.Len(t, byName, 4)

	a := byName["g04-sk@a"]
	require.NotNil(t, a)
	assert.True(t, a.Installed)
	assert.True(t, a.Enabled)
	assert.True(t, a.Running)
	assert.Equal(t, "g04 templated socket a", a.Description)
	// an instance that does not load is not a socket on this host
	assert.Nil(t, byName["gone@b"])
}

// A show that fails keeps the instance with what list-units reported.
func TestSystemdTimerManagerListKeepsInstanceWhenShowFails(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Family: []string{"linux"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"systemctl list-unit-files --type timer --all": {
				Stdout: "UNIT FILE                      STATE    PRESET\nrefresh-policy-routes@.timer   static   -\n\n1 unit files listed.\n",
			},
			"systemctl list-units --type timer --all": {
				Stdout: "  UNIT                             LOAD   ACTIVE   SUB     DESCRIPTION\n" +
					"  refresh-policy-routes@ens5.timer loaded active   waiting refresh-policy-routes@ens5.timer\n\n1 loaded units listed.\n",
			},
			"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description refresh-policy-routes@ens5.timer": {
				ExitStatus: 1,
			},
		},
	}))
	require.NoError(t, err)

	timers, err := (&SystemdTimerManager{conn: mockConn}).List()
	require.NoError(t, err)
	require.Len(t, timers, 2)
	ens5 := timers[1]
	assert.Equal(t, "refresh-policy-routes@ens5", ens5.Name)
	assert.True(t, ens5.Installed)
	assert.True(t, ens5.Running)
}
