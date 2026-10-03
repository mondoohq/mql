// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseSystemdTimerUnitFiles(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"UNIT FILE                    STATE    PRESET",
		"apt-daily.timer              enabled  enabled",
		"apt-daily-upgrade.timer      enabled  enabled",
		"e2scrub_all.timer            disabled enabled",
		"fstrim.timer                 disabled enabled",
		"logrotate.timer              static   enabled",
		"man-db.timer                 masked   enabled",
		"",
		"6 unit files listed.",
		"",
	}, "\n"))

	timers, err := ParseSystemdTimerUnitFiles(input)
	require.NoError(t, err)
	require.Len(t, timers, 6)

	// enabled timer
	assert.Equal(t, "apt-daily", timers[0].Name)
	assert.True(t, timers[0].Installed)
	assert.True(t, timers[0].Enabled)
	assert.False(t, timers[0].Masked)
	assert.False(t, timers[0].Static)

	// disabled timer
	assert.Equal(t, "e2scrub_all", timers[2].Name)
	assert.False(t, timers[2].Enabled)

	// static timer
	assert.Equal(t, "logrotate", timers[4].Name)
	assert.True(t, timers[4].Static)
	assert.False(t, timers[4].Enabled)

	// masked timer
	assert.Equal(t, "man-db", timers[5].Name)
	assert.True(t, timers[5].Masked)
	assert.False(t, timers[5].Enabled)
}

func TestParseSystemdTimerListUnits(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"  UNIT                       LOAD      ACTIVE   SUB     DESCRIPTION",
		"  apt-daily.timer            loaded    active   waiting Daily apt download activities",
		"  apt-daily-upgrade.timer    loaded    active   waiting Daily apt upgrade and clean activities",
		"  fstrim.timer               loaded    inactive dead    Discard unused blocks once a week",
		"● missing.timer              not-found inactive dead    missing.timer",
		"",
		"LOAD   = ...",
		"ACTIVE = ...",
		"SUB    = ...",
		"",
		"4 loaded units listed.",
		"",
	}, "\n"))

	timers, err := ParseSystemdTimerListUnits(input)
	require.NoError(t, err)
	require.Len(t, timers, 4)

	assert.Equal(t, "apt-daily", timers["apt-daily"].Name)
	assert.True(t, timers["apt-daily"].Running)
	assert.True(t, timers["apt-daily"].Installed)
	assert.Equal(t, "Daily apt download activities", timers["apt-daily"].Description)

	assert.False(t, timers["fstrim"].Running)
	assert.True(t, timers["fstrim"].Installed)

	assert.False(t, timers["missing"].Running)
	assert.False(t, timers["missing"].Installed)
}

func TestSystemdTimerManagerList(t *testing.T) {
	const listFilesCmd = "systemctl list-unit-files --type timer --all"
	const listUnitsCmd = "systemctl list-units --type timer --all"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			listFilesCmd: {
				Stdout: strings.Join([]string{
					"UNIT FILE                STATE    PRESET",
					"apt-daily.timer          enabled  enabled",
					"fstrim.timer             disabled enabled",
					"",
					"2 unit files listed.",
					"",
				}, "\n"),
			},
			listUnitsCmd: {
				Stdout: strings.Join([]string{
					"  UNIT              LOAD   ACTIVE   SUB     DESCRIPTION",
					"  apt-daily.timer   loaded active   waiting Daily apt download activities",
					"",
					"LOAD   = ...",
					"",
					"1 loaded units listed.",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdTimerManager{conn: mockConn}
	timers, err := mgr.List()
	require.NoError(t, err)
	require.Len(t, timers, 2)

	timerMap := map[string]*SystemdTimer{}
	for _, timer := range timers {
		timerMap[timer.Name] = timer
	}

	// apt-daily: in both lists, active
	assert.True(t, timerMap["apt-daily"].Enabled)
	assert.True(t, timerMap["apt-daily"].Running)
	assert.Equal(t, "Daily apt download activities", timerMap["apt-daily"].Description)

	// fstrim: only in unit-files, not running
	assert.False(t, timerMap["fstrim"].Enabled)
	assert.False(t, timerMap["fstrim"].Running)
}

func TestSystemdTimerManagerGet(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description apt-daily.timer"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=apt-daily.timer",
					"Description=Daily apt download activities",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdTimerManager{conn: mockConn}
	timer, err := mgr.Get("apt-daily")
	require.NoError(t, err)

	assert.Equal(t, "apt-daily", timer.Name)
	assert.Equal(t, "Daily apt download activities", timer.Description)
	assert.True(t, timer.Installed)
	assert.True(t, timer.Running)
	assert.True(t, timer.Enabled)
	assert.False(t, timer.Masked)
	assert.False(t, timer.Static)
}

func TestSystemdTimerManagerGetNotFound(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description missing.timer"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=missing.timer",
					"Description=missing.timer",
					"LoadState=not-found",
					"ActiveState=inactive",
					"UnitFileState=",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdTimerManager{conn: mockConn}
	timer, err := mgr.Get("missing")
	require.Nil(t, timer)
	require.ErrorIs(t, err, ErrServiceNotFound)
}

func TestShowTimerProperties(t *testing.T) {
	// Output of a live Ubuntu 20.04 host (systemd 245). systemd has no
	// OnCalendar property; the calendar is inside TimersCalendar.
	const showCmd = "systemctl show --property=Unit,TimersCalendar,Persistent apt-daily.timer"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Unit=apt-daily.service",
					"TimersCalendar={ OnCalendar=*-*-* 06,18:00:00 ; next_elapse=n/a }",
					"Persistent=yes",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdTimerManager{conn: mockConn}
	props, err := mgr.ShowTimerProperties("apt-daily")
	require.NoError(t, err)

	assert.Equal(t, "apt-daily.service", props["Unit"])
	assert.Equal(t, "*-*-* 06,18:00:00", props["OnCalendar"])
	assert.Equal(t, "yes", props["Persistent"])
	assert.NotContains(t, props, "TimersCalendar")
}

func TestParseTimersCalendar(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		// live Ubuntu 26.04 (systemd 259)
		{"one expression", "{ OnCalendar=*-*-* 03:00:00 ; next_elapse=Sat 2026-10-03 03:00:00 UTC }", "*-*-* 03:00:00", true},
		{"null next elapse", "{ OnCalendar=*-*-* 06,18:00:00 ; next_elapse=(null) }", "*-*-* 06,18:00:00", true},
		{"several expressions", "{ OnCalendar=Mon *-*-* 00:00:00 ; next_elapse=n/a }\n{ OnCalendar=*-*-01 12:00:00 ; next_elapse=n/a }", "Mon *-*-* 00:00:00\n*-*-01 12:00:00", true},
		{"no calendar trigger", "", "", true},
		// live Ubuntu 16.04 (systemd 229) and 18.04 (systemd 237)
		{"unprintable", "[unprintable]", "", false},
		{"unknown shape", "{ OnCalendar=daily }", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseTimersCalendar(tc.raw)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// systemd 229 and 237 print TimersCalendar as "[unprintable]", so the
// calendar comes from the unit file and its drop-ins. Output and unit file
// from a live Ubuntu 16.04 host.
func TestShowTimerPropertiesReadsUnitFileOnOldSystemd(t *testing.T) {
	const showCmd = "systemctl show --property=Unit,TimersCalendar,Persistent apt-daily.timer"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"ubuntu", "linux"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {Stdout: strings.Join([]string{
				"Unit=apt-daily.service",
				"TimersCalendar=[unprintable]",
				"Persistent=yes",
				"",
			}, "\n")},
		},
	}))
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/apt-daily.timer", []byte(`[Unit]
Description=Daily apt download activities

[Timer]
OnCalendar=*-*-* 6,18:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
`), 0o644))
	conn := &fsConn{Connection: mockConn, fs: fs}

	t.Run("unit file", func(t *testing.T) {
		props, err := NewSystemdTimerManager(conn).ShowTimerProperties("apt-daily")
		require.NoError(t, err)
		assert.Equal(t, "*-*-* 6,18:00", props["OnCalendar"])
		// systemctl still answers the rest
		assert.Equal(t, "yes", props["Persistent"])
		assert.Equal(t, "apt-daily.service", props["Unit"])
		assert.NotContains(t, props, "TimersCalendar")
	})

	t.Run("drop-in replaces the schedule", func(t *testing.T) {
		require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/apt-daily.timer.d/override.conf", []byte(`[Timer]
OnCalendar=
OnCalendar=*-*-* 04:00
OnCalendar=Sun 05:00
`), 0o644))
		props, err := NewSystemdTimerManager(conn).ShowTimerProperties("apt-daily")
		require.NoError(t, err)
		assert.Equal(t, "*-*-* 04:00\nSun 05:00", props["OnCalendar"])
	})
}

// A monotonic timer prints "[unprintable]" on systemd 229 as well; its unit
// file has no OnCalendar, so the calendar stays absent.
func TestShowTimerPropertiesMonotonicOnOldSystemd(t *testing.T) {
	conn := systemdFallbackConn(t, map[string]*mock.Command{
		buildShowPropertyCommand("Unit,TimersCalendar,Persistent", "dnf-makecache.timer"): {Stdout: strings.Join([]string{
			"Unit=dnf-makecache.service",
			"TimersMonotonic=[unprintable]",
			"TimersCalendar=[unprintable]",
			"Persistent=no",
			"",
		}, "\n")},
	})

	props, err := NewSystemdTimerManager(conn).ShowTimerProperties("dnf-makecache")
	require.NoError(t, err)
	assert.NotContains(t, props, "OnCalendar")
	assert.Equal(t, "dnf-makecache.service", props["Unit"])
}

func TestParseSystemdTimerAndSocketListUnitsJobColumn(t *testing.T) {
	timers, err := ParseSystemdTimerListUnits(strings.NewReader(strings.Join([]string{
		"  UNIT             LOAD   ACTIVE   SUB     JOB  DESCRIPTION",
		"  g04-cal.timer    loaded active   waiting      g04 calendar timer",
		"  g04-mono.timer   loaded inactive dead    stop g04 monotonic timer",
		"",
	}, "\n")))
	require.NoError(t, err)
	assert.Equal(t, "g04 calendar timer", timers["g04-cal"].Description)
	assert.Equal(t, "g04 monotonic timer", timers["g04-mono"].Description)

	sockets, err := ParseSystemdSocketListUnits(strings.NewReader(strings.Join([]string{
		"  UNIT             LOAD   ACTIVE     SUB       JOB   DESCRIPTION",
		"  g04.socket       loaded activating listening start g04 socket",
		"● g04-svc.socket   loaded failed     failed          g04 socket activating other service",
		"",
	}, "\n")))
	require.NoError(t, err)
	assert.Equal(t, "g04 socket", sockets["g04"].Description)
	assert.Equal(t, "g04 socket activating other service", sockets["g04-svc"].Description)
}
