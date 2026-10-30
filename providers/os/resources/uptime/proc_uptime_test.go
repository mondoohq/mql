// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uptime_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/uptime"
)

func TestParseProcUptime(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    time.Duration
	}{
		{"typical", "350735.47 234388.90\n", 350735470 * time.Millisecond},
		{"freshly booted", "0.42 0.11\n", 420 * time.Millisecond},
		{"no trailing newline", "1140.00 900.00", 19 * time.Minute},
		// a single-CPU kernel prints one column on some very old builds
		{"one column", "60.00\n", time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := uptime.ParseProcUptime(tc.content)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseProcUptime_Rejected(t *testing.T) {
	for _, content := range []string{"", "\n", "not-a-number 1.0\n", "-1.0 0.0\n"} {
		_, err := uptime.ParseProcUptime(content)
		assert.Error(t, err, "content %q", content)
	}
}

// A minimal image does not ship procps, so `uptime` exits 127 with nothing on
// stdout. That used to surface as `could not parse uptime: ` and os.uptime read
// null. /proc/uptime is always there and needs no binary.
func TestUptimeOnLinux_FallsBackToProcWhenCommandIsMissing(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Version: "13", Family: []string{"debian", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"uptime": {Stderr: "sh: 1: uptime: not found\n", ExitStatus: 127},
		},
		Files: map[string]*mock.MockFileData{
			"/proc/uptime": {Content: "1140.00 900.00\n"},
		},
	}))
	require.NoError(t, err)

	ut, err := uptime.New(conn)
	require.NoError(t, err)

	d, err := ut.Duration()
	require.NoError(t, err)
	assert.Equal(t, "19m0s", d.String())
}

// A host with neither reports both reasons rather than only the parse failure.
func TestUptimeOnLinux_ReportsBothFailures(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Version: "13", Family: []string{"debian", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"uptime": {Stderr: "sh: 1: uptime: not found\n", ExitStatus: 127},
		},
	}))
	require.NoError(t, err)

	ut, err := uptime.New(conn)
	require.NoError(t, err)

	_, err = ut.Duration()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uptime exited 127")
	assert.Contains(t, err.Error(), "/proc/uptime")
}

// openSUSE Leap installs GNU coreutils' `uptime`, not the procps one. It
// prints the day count with no comma after it -- "up 1 day 10:51," where
// procps prints "up 1 day, 10:53," -- which the parser rejected outright, so
// os.uptime read null on every openSUSE Leap host even though the command was
// right there and working.
func TestParseUnixUptime_CoreutilsNoCommaAfterDays(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want time.Duration
	}{
		{
			// coreutils 8.32, openSUSE Leap 15.6
			name: "coreutils leap",
			line: " 16:31:12  up 1 day 10:51,  0 users,  load average: 0.05, 0.10, 0.19",
			want: 34*time.Hour + 51*time.Minute,
		},
		{
			name: "coreutils several days",
			line: " 09:02:11  up 12 days 3:07,  2 users,  load average: 0.00, 0.01, 0.05",
			want: 12*24*time.Hour + 3*time.Hour + 7*time.Minute,
		},
		{
			// procps-ng, ubuntu 24.04 -- unchanged
			name: "procps",
			line: " 16:32:48 up 1 day, 10:53,  0 user,  load average: 0.13, 0.11, 0.18",
			want: 34*time.Hour + 53*time.Minute,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := uptime.ParseUnixUptime(tc.line)
			require.NoError(t, err)
			assert.Equal(t, tc.want, time.Duration(res.Duration))
		})
	}
}
