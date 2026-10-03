// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `systemctl list-units --type service --all` on Rocky Linux 9 (systemd 252)
// while g04-slow.service has a queued start job, which adds a JOB column.
func TestParseSystemdListUnitsJobColumn(t *testing.T) {
	data, err := os.ReadFile("testdata/rocky9-list-units-job-column.txt")
	require.NoError(t, err)

	services, err := ParseSystemdListUnits(strings.NewReader(string(data)))
	require.NoError(t, err)

	require.Contains(t, services, "g04-slow")
	assert.Equal(t, "g04 slow start job", services["g04-slow"].Description)
	assert.False(t, services["g04-slow"].Running)
	// rows without a job, and failed rows marked with "●", keep their whole
	// description
	assert.Equal(t, "g04 denylist unit", services["g04-deny"].Description)
	assert.Equal(t, "g04 failing unit", services["g04-fail"].Description)
	assert.Equal(t, "dnf makecache", services["dnf-makecache"].Description)
}

func TestSystemdListUnitsJobColumn(t *testing.T) {
	assert.Equal(t, -1, systemdListUnitsJobColumn("  UNIT          LOAD   ACTIVE SUB     DESCRIPTION\n  a.service     loaded active running start job\n"))
	assert.Equal(t, -1, systemdListUnitsJobColumn(""))
	assert.Equal(t, 48, systemdListUnitsJobColumn("  UNIT                LOAD   ACTIVE     SUB     JOB   DESCRIPTION\n"))
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
