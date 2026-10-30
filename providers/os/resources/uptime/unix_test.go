// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uptime_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/uptime"
)

func TestLinuxUptime(t *testing.T) {
	// uptime
	data := " 21:00:04 up 1 day,  5:29,  0 users,  load average: 0.00, 0.13, 0.22"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           106140000000000,
		Users:              0,
		LoadOneMinute:      float64(0.0),
		LoadFiveMinutes:    float64(0.13),
		LoadFifteenMinutes: float64(0.22),
	}, duration)
	assert.Equal(t, "29h29m0s", time.Duration(duration.Duration).String())

	data = "23:41:57 up 16 min,  0 users,  load average: 0.06, 0.02, 0.00"
	duration, err = uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           960000000000,
		Users:              0,
		LoadOneMinute:      float64(0.06),
		LoadFiveMinutes:    float64(0.02),
		LoadFifteenMinutes: float64(0.00),
	}, duration)
	assert.Equal(t, "16m0s", time.Duration(duration.Duration).String())
}

func TestAlpineUptime(t *testing.T) {
	// alpine
	data := " 08:45:41 up 22 min,  load average: 0.19, 0.15, 0.09"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           1320000000000,
		Users:              0,
		LoadOneMinute:      float64(0.19),
		LoadFiveMinutes:    float64(0.15),
		LoadFifteenMinutes: float64(0.09),
	}, duration)
	assert.Equal(t, "22m0s", time.Duration(duration.Duration).String())
}

func TestLcNumericDeUptime(t *testing.T) {
	// LC_NUMERIC=de_DE.UTF-8 on Ubuntu 22.04
	data := " 06:47:21 up 1 day, 14:18,  1 user,  load average: 0,19, 0,15, 0,09"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           137880000000000,
		Users:              1,
		LoadOneMinute:      float64(0.19),
		LoadFiveMinutes:    float64(0.15),
		LoadFifteenMinutes: float64(0.09),
	}, duration)
	assert.Equal(t, "38h18m0s", time.Duration(duration.Duration).String())
}

func TestDebianUptime(t *testing.T) {
	// debian
	data := " 08:45:19 up 21 min,  0 users,  load average: 0.10, 0.13, 0.09"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           1260000000000,
		Users:              0,
		LoadOneMinute:      float64(0.10),
		LoadFiveMinutes:    float64(0.13),
		LoadFifteenMinutes: float64(0.09),
	}, duration)
	assert.Equal(t, "21m0s", time.Duration(duration.Duration).String())
}

func TestRhelUptime(t *testing.T) {
	// rhel
	data := " 12:27:22 up 8 min,  1 user,  load average: 0.01, 0.02, 0.00"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           480000000000,
		Users:              1,
		LoadOneMinute:      float64(0.01),
		LoadFiveMinutes:    float64(0.02),
		LoadFifteenMinutes: float64(0.00),
	}, duration)
	assert.Equal(t, "8m0s", time.Duration(duration.Duration).String())

	data = "13:24:35 up  1:05,  2 users,  load average: 0.00, 0.00, 0.00"
	duration, err = uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           3900000000000,
		Users:              2,
		LoadOneMinute:      float64(0.00),
		LoadFiveMinutes:    float64(0.00),
		LoadFifteenMinutes: float64(0.00),
	}, duration)
	assert.Equal(t, "1h5m0s", time.Duration(duration.Duration).String())
}

func TestBusyboxUptime(t *testing.T) {
	data := " 08:56:57 up 33 min,  0 users,  load average: 0.09, 0.09, 0.08"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           1980000000000,
		Users:              0,
		LoadOneMinute:      float64(0.09),
		LoadFiveMinutes:    float64(0.09),
		LoadFifteenMinutes: float64(0.08),
	}, duration)
	assert.Equal(t, "33m0s", time.Duration(duration.Duration).String())
}

func TestMacOSUptime(t *testing.T) {
	// uptime
	data := "23:04  up 24 days, 13:07, 9 users, load averages: 4.81 5.21 5.15"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           2120820000000000,
		Users:              9,
		LoadOneMinute:      float64(4.81),
		LoadFiveMinutes:    float64(5.21),
		LoadFifteenMinutes: float64(5.15),
	}, duration)
	assert.Equal(t, "589h7m0s", time.Duration(duration.Duration).String())

	data = "10:52  up 38 mins, 9 users, load averages: 2.27 2.54 3.72"
	duration, err = uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           2280000000000,
		Users:              9,
		LoadOneMinute:      float64(2.27),
		LoadFiveMinutes:    float64(2.54),
		LoadFifteenMinutes: float64(3.72),
	}, duration)
	assert.Equal(t, "38m0s", time.Duration(duration.Duration).String())

	data = "13:16  up 8 days, 13 mins, 6 users, load averages: 2.56 2.68 2.91"
	duration, err = uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           691980000000000,
		Users:              6,
		LoadOneMinute:      float64(2.56),
		LoadFiveMinutes:    float64(2.68),
		LoadFifteenMinutes: float64(2.91),
	}, duration)
	assert.Equal(t, "192h13m0s", time.Duration(duration.Duration).String())

	// When the minutes component is exactly zero, macOS prints "N hrs"
	// instead of "N:00" — for one minute every hour the old regex failed
	// and the uptime resource errored. Captured verbatim from a real scan.
	data = "12:18  up 11 days, 16 hrs, 1 user, load averages: 7.12 6.59 4.92"
	duration, err = uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           (11*24 + 16) * int64(time.Hour),
		Users:              1,
		LoadOneMinute:      float64(7.12),
		LoadFiveMinutes:    float64(6.59),
		LoadFifteenMinutes: float64(4.92),
	}, duration)
	assert.Equal(t, "280h0m0s", time.Duration(duration.Duration).String())

	// Singular form, one hour exactly.
	data = "9:05  up 1 hr, 2 users, load averages: 1.10 0.90 0.80"
	duration, err = uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           int64(time.Hour),
		Users:              2,
		LoadOneMinute:      float64(1.10),
		LoadFiveMinutes:    float64(0.90),
		LoadFifteenMinutes: float64(0.80),
	}, duration)
	assert.Equal(t, "1h0m0s", time.Duration(duration.Duration).String())
}

func TestFreebsdUptime(t *testing.T) {
	data := " 9:57AM  up 24 mins, 1 user, load averages: 0.64, 0.50, 0.37"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           1440000000000,
		Users:              1,
		LoadOneMinute:      float64(0.64),
		LoadFiveMinutes:    float64(0.5),
		LoadFifteenMinutes: float64(0.37),
	}, duration)
	assert.Equal(t, "24m0s", time.Duration(duration.Duration).String())
}

// Solaris pluralizes with "(s)" rather than a bare "s". Verbatim output from an
// Oracle Solaris 11.4.86 host.
func TestSolarisUptimeMinutes(t *testing.T) {
	data := "  7:28am  up 27 min(s),  0 users,  load average: 0.02, 0.01, 0.03"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, &uptime.UnixUptimeResult{
		Duration:           int64(27 * time.Minute),
		Users:              0,
		LoadOneMinute:      float64(0.02),
		LoadFiveMinutes:    float64(0.01),
		LoadFifteenMinutes: float64(0.03),
	}, duration)
	assert.Equal(t, "27m0s", time.Duration(duration.Duration).String())
}

func TestSolarisUptimeDaysAndClock(t *testing.T) {
	data := " 10:47am  up 5 day(s), 21:03,  1 user,  load average: 0.10, 0.20, 0.30"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, "141h3m0s", time.Duration(duration.Duration).String())
	assert.Equal(t, 1, duration.Users)
}

func TestSolarisUptimeHours(t *testing.T) {
	data := " 10:47am  up 2 hr(s), 15 min(s),  3 users,  load average: 0.10, 0.20, 0.30"
	duration, err := uptime.ParseUnixUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, "2h15m0s", time.Duration(duration.Duration).String())
}
