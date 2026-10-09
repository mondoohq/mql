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

// `chronyc -n -c tracking` on Rocky Linux 9 synchronized to a pool server.
const rocky9ChronycTracking = "C6336414,198.51.100.20,3,1760040765.402166235,-0.000004012,-0.000001789,0.000021553,-7.462,-0.001,0.026,0.000474853,0.000140421,1024.4,Normal\n"

func newOsDateMock(t *testing.T, platform *inventory.Platform, data *mock.TomlData) *mqlOsDate {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(data))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := CreateResource(rt, "os.date", nil)
	require.NoError(t, err)
	return res.(*mqlOsDate)
}

var debianPlatform = &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix"}}

func TestOsDateTimeSyncTimesyncd(t *testing.T) {
	d := newOsDateMock(t, debianPlatform, &mock.TomlData{Commands: map[string]*mock.Command{
		"timedatectl show --no-pager":              {Stdout: debian13TimedatectlShow},
		"systemctl is-active -- systemd-timesyncd": {ExitStatus: 0},
		"timedatectl show-timesync --no-pager":     {Stdout: debian13ShowTimesync},
		// must not be preferred over the running timesyncd
		"chronyc -n -c tracking": {Stdout: rocky9ChronycTracking},
	}})

	assert.True(t, d.GetSynchronized().Data)
	assert.Equal(t, "169.254.169.123", d.GetTimeSource().Data)
}

func TestOsDateTimeSyncChrony(t *testing.T) {
	// timesyncd is not running, so it is not asked (that would start it),
	// and the source comes from chronyd.
	d := newOsDateMock(t, &inventory.Platform{Name: "rocky", Family: []string{"redhat", "linux", "unix"}}, &mock.TomlData{Commands: map[string]*mock.Command{
		"timedatectl show --no-pager":              {Stdout: "Timezone=UTC\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n"},
		"systemctl is-active -- systemd-timesyncd": {ExitStatus: 3},
		"timedatectl show-timesync --no-pager":     {Stdout: debian13ShowTimesync},
		"chronyc -n -c tracking":                   {Stdout: rocky9ChronycTracking},
	}})

	assert.True(t, d.GetSynchronized().Data)
	assert.Equal(t, "198.51.100.20", d.GetTimeSource().Data)
}

func TestOsDateTimeSyncNoSystemd(t *testing.T) {
	// Alpine with chronyd: no timedatectl, so chronyd answers both.
	d := newOsDateMock(t, &inventory.Platform{Name: "alpine", Family: []string{"linux", "unix"}}, &mock.TomlData{Commands: map[string]*mock.Command{
		"chronyc -n -c tracking": {Stdout: "00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n"},
	}})

	synced := d.GetSynchronized()
	require.NoError(t, synced.Error)
	assert.False(t, synced.IsNull())
	assert.False(t, synced.Data)
	assert.True(t, d.GetTimeSource().IsNull())
}

func TestOsDateTimeSyncNotSynchronizedHasNoSource(t *testing.T) {
	// timesyncd has picked a server it has not synchronized to yet
	d := newOsDateMock(t, debianPlatform, &mock.TomlData{Commands: map[string]*mock.Command{
		"timedatectl show --no-pager":              {Stdout: "Timezone=Etc/UTC\nNTP=yes\nNTPSynchronized=no\n"},
		"systemctl is-active -- systemd-timesyncd": {ExitStatus: 0},
		"timedatectl show-timesync --no-pager":     {Stdout: debian13ShowTimesync},
	}})

	assert.False(t, d.GetSynchronized().Data)
	assert.True(t, d.GetTimeSource().IsNull())
}

func TestOsDateTimeSyncUnknown(t *testing.T) {
	// no timedatectl, no chronyc: unknown is null, not false
	d := newOsDateMock(t, debianPlatform, &mock.TomlData{})

	synced := d.GetSynchronized()
	require.NoError(t, synced.Error)
	assert.True(t, synced.IsNull())
	source := d.GetTimeSource()
	require.NoError(t, source.Error)
	assert.True(t, source.IsNull())
}

func TestOsDateTimeSyncMacOS(t *testing.T) {
	d := newOsDateMock(t, &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix"}}, &mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/etc/ntp.conf": {Path: "/etc/ntp.conf", Content: "server time.apple.com\n"},
		},
	})

	assert.True(t, d.GetSynchronized().IsNull())
	assert.Equal(t, "time.apple.com", d.GetTimeSource().Data)
}

func TestOsDateUnixOffset(t *testing.T) {
	d := newOsDateMock(t, debianPlatform, &mock.TomlData{
		Commands: map[string]*mock.Command{
			"date -u +%Y-%m-%dT%H:%M:%SZ": {Stdout: "2026-10-09T22:12:45Z\n"},
			"date +%z":                    {Stdout: "+0545\n"},
		},
		Files: map[string]*mock.MockFileData{
			"/etc/timezone": {Path: "/etc/timezone", Content: "Asia/Kathmandu\n"},
		},
	})

	assert.Equal(t, "Asia/Kathmandu", d.GetTimezone().Data)
	assert.Equal(t, int64(20700), d.GetUtcOffset().Data)
	assert.True(t, d.GetWindowsTimezone().IsNull())
}
