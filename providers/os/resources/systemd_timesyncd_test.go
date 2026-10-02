// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// `timedatectl show-timesync --no-pager` on Debian 13 (systemd 257) with a
// server configured in a timesyncd.conf drop-in.
const debian13ShowTimesync = `SystemNTPServers=169.254.169.123
FallbackNTPServers=169.254.169.123 fd00:ec2::123 0.debian.pool.ntp.org 1.debian.pool.ntp.org
ServerName=169.254.169.123
ServerAddress=169.254.169.123
RootDistanceMaxUSec=5s
PollIntervalMinUSec=32s
PollIntervalMaxUSec=34min 8s
PollIntervalUSec=4min 16s
NTPMessage={ Leap=0, Version=4, Mode=4, Stratum=3, Precision=-18, RootDelay=167us, RootDispersion=335us, Reference=A9FEA97A, OriginateTimestamp=Fri 2026-10-02 11:24:34 UTC, ReceiveTimestamp=Fri 2026-10-02 11:24:34 UTC, TransmitTimestamp=Fri 2026-10-02 11:24:34 UTC, DestinationTimestamp=Fri 2026-10-02 11:24:34 UTC, Ignored=no, PacketCount=3, Jitter=196us }
Frequency=539969
`

// The same command on a stock Debian 12 (systemd 252), where no NTP= server
// is configured: timedatectl leaves the empty SystemNTPServers line out.
const debian12StockShowTimesync = `FallbackNTPServers=169.254.169.123 fd00:ec2::123
ServerName=169.254.169.123
ServerAddress=169.254.169.123
RootDistanceMaxUSec=5s
PollIntervalMinUSec=32s
PollIntervalMaxUSec=34min 8s
PollIntervalUSec=8min 32s
NTPMessage={ Leap=0, Version=4, Mode=4, Stratum=3, Precision=-18, RootDelay=167us, RootDispersion=183us, Reference=A9FEA97A, OriginateTimestamp=Fri 2026-10-02 11:07:09 UTC, ReceiveTimestamp=Fri 2026-10-02 11:07:09 UTC, TransmitTimestamp=Fri 2026-10-02 11:07:09 UTC, DestinationTimestamp=Fri 2026-10-02 11:07:09 UTC, Ignored=yes, PacketCount=5, Jitter=71us }
Frequency=-36834
`

// `timedatectl show --no-pager` on Debian 13.
const debian13TimedatectlShow = `Timezone=Etc/UTC
LocalRTC=no
CanNTP=yes
NTP=yes
NTPSynchronized=yes
TimeUSec=Fri 2026-10-02 11:25:51 UTC
RTCTimeUSec=Fri 2026-10-02 11:25:51 UTC
`

func TestParseTimesyncProperties(t *testing.T) {
	p := parseTimesyncProperties(debian13ShowTimesync)
	assert.Equal(t, []string{"169.254.169.123"}, p.servers)
	assert.Equal(t, []string{"169.254.169.123", "fd00:ec2::123", "0.debian.pool.ntp.org", "1.debian.pool.ntp.org"}, p.fallbackServers)
	require.NotNil(t, p.serverName)
	assert.Equal(t, "169.254.169.123", *p.serverName)
	require.NotNil(t, p.serverAddress)
	assert.Equal(t, "169.254.169.123", *p.serverAddress)
	require.NotNil(t, p.pollIntervalUSec)
	assert.Equal(t, int64(256_000_000), *p.pollIntervalUSec)
	require.NotNil(t, p.leapStatus)
	assert.Equal(t, "normal", *p.leapStatus)
}

func TestParseTimesyncPropertiesNoConfiguredServers(t *testing.T) {
	p := parseTimesyncProperties(debian12StockShowTimesync)
	// a running daemon that lists no servers has none: empty, not null
	assert.NotNil(t, p.servers)
	assert.Empty(t, p.servers)
	assert.Equal(t, []string{"169.254.169.123", "fd00:ec2::123"}, p.fallbackServers)
	require.NotNil(t, p.pollIntervalUSec)
	assert.Equal(t, int64(512_000_000), *p.pollIntervalUSec)
}

func TestParseTimesyncPropertiesBeforeFirstAnswer(t *testing.T) {
	// Before a server answers, the daemon has picked no server and holds no
	// NTP message, and timedatectl prints neither.
	p := parseTimesyncProperties("SystemNTPServers=192.0.2.123\nFallbackNTPServers=\nPollIntervalUSec=0\n")
	assert.Equal(t, []string{"192.0.2.123"}, p.servers)
	assert.NotNil(t, p.fallbackServers)
	assert.Empty(t, p.fallbackServers)
	assert.Nil(t, p.serverName)
	assert.Nil(t, p.serverAddress)
	assert.Nil(t, p.leapStatus)
}

func TestParseTimesyncPropertiesLeapIndicator(t *testing.T) {
	for leap, want := range map[string]string{"0": "normal", "1": "insert-second", "2": "delete-second", "3": "unknown"} {
		p := parseTimesyncProperties("NTPMessage={ Leap=" + leap + ", Version=4, Mode=4, Stratum=3 }\n")
		require.NotNil(t, p.leapStatus, leap)
		assert.Equal(t, want, *p.leapStatus, leap)
	}
}

func TestParseSystemdTimespanUSec(t *testing.T) {
	cases := map[string]int64{
		"4min 16s":  256_000_000,
		"34min 8s":  2_048_000_000,
		"17min 4s":  1_024_000_000,
		"32s":       32_000_000,
		"5s":        5_000_000,
		"500ms":     500_000,
		"1h 8min":   4_080_000_000,
		"1.5s":      1_500_000,
		"256000000": 256_000_000,
		"0":         0,
	}
	for in, want := range cases {
		got, ok := parseSystemdTimespanUSec(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "infinity", "4min 16", "4 parsecs", "min"} {
		_, ok := parseSystemdTimespanUSec(in)
		assert.False(t, ok, in)
	}
}

func TestTimesyncd_StatusFallback(t *testing.T) {
	// systemd < 239 (e.g. v237 on Ubuntu 18.04) has no `timedatectl show`
	// verb, so `synchronized` falls back to parsing `timedatectl status`.
	status := `                      Local time: Wed 2026-06-17 06:34:18 CEST
                  Universal time: Wed 2026-06-17 04:34:18 UTC
                        RTC time: Wed 2026-06-17 04:34:18
                       Time zone: Europe/Berlin (CEST, +0200)
       System clock synchronized: yes
systemd-timesyncd.service active: yes
                 RTC in local TZ: no
`
	assert.True(t, parseTimedatectlStatusSynchronized(status))

	notSynced := `       System clock synchronized: no
systemd-timesyncd.service active: yes
`
	assert.False(t, parseTimedatectlStatusSynchronized(notSynced))
}

func TestTimesyncd_StatusFallbackSystemd232(t *testing.T) {
	// `timedatectl status` on Debian 9 (systemd 232) labels the line
	// "NTP synchronized".
	status := `      Local time: Fri 2026-10-02 11:25:48 UTC
  Universal time: Fri 2026-10-02 11:25:48 UTC
        RTC time: Fri 2026-10-02 11:25:48
       Time zone: Etc/UTC (UTC, +0000)
 Network time on: yes
NTP synchronized: yes
 RTC in local TZ: no
`
	assert.True(t, parseTimedatectlStatusSynchronized(status))
}

func TestTimesyncd_StatusFallbackEdgeCases(t *testing.T) {
	// Missing line -> not synchronized rather than a false positive.
	assert.False(t, parseTimedatectlStatusSynchronized(""))
	assert.False(t, parseTimedatectlStatusSynchronized("Time zone: UTC (UTC, +0000)\n"))

	// Case-insensitive value, and the "active" line must not be mistaken
	// for the synchronized line.
	assert.True(t, parseTimedatectlStatusSynchronized("System clock synchronized: Yes\n"))
	assert.False(t, parseTimedatectlStatusSynchronized("systemd-timesyncd.service active: yes\n"))
}

func newTimesyncdMock(t *testing.T, activeExit int) *mqlSystemdTimesyncd {
	t.Helper()
	commands := map[string]*mock.Command{
		"systemctl is-active -- systemd-timesyncd": {ExitStatus: activeExit},
		"timedatectl show --no-pager":              {Stdout: debian13TimedatectlShow},
		// Answers as a running daemon would, so a query of an inactive
		// daemon would read these values instead of null.
		"timedatectl show-timesync --no-pager": {Stdout: debian13ShowTimesync},
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := NewResource(rt, "systemd.timesyncd", nil)
	require.NoError(t, err)
	return res.(*mqlSystemdTimesyncd)
}

func TestTimesyncdInactiveIsNotQueried(t *testing.T) {
	// systemctl is-active exits 3 for an inactive unit
	ts := newTimesyncdMock(t, 3)

	assert.False(t, ts.GetActive().Data)
	// the clock state comes from timedated, not from timesyncd
	assert.True(t, ts.GetSynchronized().Data)

	for name, v := range map[string]plugin.TValue[[]any]{
		"servers":         *ts.GetServers(),
		"fallbackServers": *ts.GetFallbackServers(),
	} {
		require.NoError(t, v.Error, name)
		assert.True(t, v.IsNull(), name)
	}
	for name, v := range map[string]plugin.TValue[string]{
		"serverName":    *ts.GetServerName(),
		"serverAddress": *ts.GetServerAddress(),
		"leapStatus":    *ts.GetLeapStatus(),
	} {
		require.NoError(t, v.Error, name)
		assert.True(t, v.IsNull(), name)
	}
	poll := ts.GetPollIntervalUSec()
	require.NoError(t, poll.Error)
	assert.True(t, poll.IsNull())
}

func TestTimesyncdActiveIsQueried(t *testing.T) {
	ts := newTimesyncdMock(t, 0)

	assert.True(t, ts.GetActive().Data)
	assert.Equal(t, []any{"169.254.169.123"}, ts.GetServers().Data)
	assert.Equal(t, "169.254.169.123", ts.GetServerName().Data)
	assert.Equal(t, int64(256_000_000), ts.GetPollIntervalUSec().Data)
	assert.Equal(t, "normal", ts.GetLeapStatus().Data)
}
