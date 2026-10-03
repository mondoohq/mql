// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// /proc of ubuntu/squid started with `-f /opt/alt.conf -NYC`: the
// entrypoint script stays pid 1 and runs squid as pid 40, whose helpers
// rename their command lines.
var squidImageProc = map[string]string{
	"/proc/1/cmdline":  "/bin/bash\x00/usr/local/bin/entrypoint.sh\x00-f\x00/opt/alt.conf\x00-NYC\x00",
	"/proc/1/stat":     "1 (entrypoint.sh) S 0 1 1 0 -1",
	"/proc/35/cmdline": "tail\x00-F\x00/var/log/squid/access.log\x00",
	"/proc/35/stat":    "35 (tail) S 1 1 1 0 -1",
	"/proc/40/cmdline": "/usr/sbin/squid\x00-f\x00/opt/alt.conf\x00-NYC\x00",
	"/proc/40/stat":    "40 (squid) S 1 1 1 0 -1",
	"/proc/41/cmdline": "(logfile-daemon)\x00/var/log/squid/access.log\x00",
	"/proc/41/stat":    "41 (log_file_daemon) S 40 41 1 0 -1",
}

const (
	squidAltConf   = "http_port 3130\nvia on\n"
	squidDecoyConf = "http_port 3129\nvia off\n"
)

// RHEL 9's squid.service and /etc/sysconfig/squid, with SQUID_CONF changed.
var squidRHELUnit = map[string]string{
	"/usr/lib/systemd/system/squid.service": "[Service]\nType=notify\nPIDFile=/run/squid.pid\nEnvironmentFile=/etc/sysconfig/squid\nExecStart=/usr/sbin/squid --foreground $SQUID_OPTS -f ${SQUID_CONF}\n",
	"/etc/sysconfig/squid":                  "SQUID_OPTS=\"\"\nSQUID_CONF=\"/etc/squid/alt.conf\"\n",
}

func squidConfOf(t *testing.T, rt *plugin.Runtime) *mqlSquidConf {
	t.Helper()
	res, err := NewResource(rt, "squid.conf", nil)
	require.NoError(t, err)
	return res.(*mqlSquidConf)
}

func TestSquidConfFollowsLaunch(t *testing.T) {
	pgrepSquid := map[string]*mock.Command{"pgrep -x 'squid'": {Stdout: "40\n41\n"}}

	t.Run("running squid's -f wins over the default path", func(t *testing.T) {
		files := mergeFiles(squidImageProc, map[string]string{
			"/opt/alt.conf":         squidAltConf,
			"/etc/squid/squid.conf": squidDecoyConf,
		})
		conf := squidConfOf(t, newLaunchRuntime(t, files, pgrepSquid, nil))
		require.NoError(t, conf.GetFile().Error)
		assert.Equal(t, "/opt/alt.conf", conf.GetFile().Data.Path.Data)
		assert.Equal(t, "on", conf.GetVia().Data)
	})

	t.Run("a running squid without -f reads the default, whatever the unit says", func(t *testing.T) {
		files := mergeFiles(squidRHELUnit, map[string]string{
			"/proc/40/cmdline":      "/usr/sbin/squid\x00-FC\x00",
			"/proc/40/stat":         "40 (squid) S 1 40 40 0 -1",
			"/etc/squid/alt.conf":   squidAltConf,
			"/etc/squid/squid.conf": squidDecoyConf,
		})
		conf := squidConfOf(t, newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'squid'": {Stdout: "40\n"}}, nil))
		assert.Equal(t, "/etc/squid/squid.conf", conf.GetFile().Data.Path.Data)
	})

	t.Run("the unit's -f when squid does not run", func(t *testing.T) {
		files := mergeFiles(squidRHELUnit, map[string]string{
			"/etc/squid/alt.conf":   squidAltConf,
			"/etc/squid/squid.conf": squidDecoyConf,
		})
		conf := squidConfOf(t, newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'squid'": {ExitStatus: 1}}, nil))
		assert.Equal(t, "/etc/squid/alt.conf", conf.GetFile().Data.Path.Data)
		assert.Equal(t, "on", conf.GetVia().Data)
	})

	t.Run("a named file that does not exist falls back to the defaults", func(t *testing.T) {
		files := mergeFiles(squidRHELUnit, map[string]string{"/etc/squid/squid.conf": squidDecoyConf})
		conf := squidConfOf(t, newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'squid'": {ExitStatus: 1}}, nil))
		assert.Equal(t, "/etc/squid/squid.conf", conf.GetFile().Data.Path.Data)
	})

	t.Run("the image's Cmd, passed to squid by its entrypoint script", func(t *testing.T) {
		image := &tar.ImageConfig{Entrypoint: []string{"entrypoint.sh"}, Cmd: []string{"-f", "/opt/alt.conf", "-NYC"}}
		files := map[string]string{"/opt/alt.conf": squidAltConf, "/etc/squid/squid.conf": squidDecoyConf}
		conf := squidConfOf(t, newLaunchRuntime(t, files, nil, image))
		assert.Equal(t, "/opt/alt.conf", conf.GetFile().Data.Path.Data)
		assert.Equal(t, "on", conf.GetVia().Data)
	})
}
