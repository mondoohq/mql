// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nginx

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcCmdline(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want LaunchArgs
		ok   bool
	}{
		{
			// /proc/<pid>/cmdline of the master on SLES and Leap 15 and 16
			// (nginx.service runs `nginx -g "daemon off;"`)
			name: "master title with -g",
			raw:  "nginx: master process /usr/sbin/nginx -g daemon off;\x00",
			want: LaunchArgs{Binary: "/usr/sbin/nginx", Globals: "daemon off;"},
			ok:   true,
		},
		{
			// Ubuntu 24.04, Debian 13, Rocky 8 and Fedora 44 master started
			// as /usr/sbin/nginx -c /etc/nginx-alt/nginx.conf -g 'worker_processes 3;'
			name: "master title with -c and -g",
			raw:  "nginx: master process /usr/sbin/nginx -c /etc/nginx-alt/nginx.conf -g worker_processes 3;\x00",
			want: LaunchArgs{Binary: "/usr/sbin/nginx", Conf: "/etc/nginx-alt/nginx.conf", Globals: "worker_processes 3;"},
			ok:   true,
		},
		{
			name: "master title with a multi-directive -g before -c",
			raw:  "nginx: master process /usr/sbin/nginx -g worker_processes 3; daemon on; -c /etc/nginx-alt/nginx.conf\x00",
			want: LaunchArgs{Binary: "/usr/sbin/nginx", Conf: "/etc/nginx-alt/nginx.conf", Globals: "worker_processes 3; daemon on;"},
			ok:   true,
		},
		{
			name: "master title, -g before -p",
			raw:  "nginx: master process nginx -g pid /run/alt.pid; -p /opt/nginx/\x00",
			want: LaunchArgs{Binary: "nginx", Prefix: "/opt/nginx/", Globals: "pid /run/alt.pid;"},
			ok:   true,
		},
		{
			// a process that kept its argv, as an emulated master does
			name: "NUL-separated argv",
			raw:  "/usr/sbin/nginx\x00-c\x00/etc/nginx-alt/nginx.conf\x00-g\x00worker_processes 3;\x00",
			want: LaunchArgs{Binary: "/usr/sbin/nginx", Conf: "/etc/nginx-alt/nginx.conf", Globals: "worker_processes 3;"},
			ok:   true,
		},
		{
			name: "attached and grouped options, last -c wins",
			raw:  "/usr/sbin/nginx\x00-c/etc/a.conf\x00-qc\x00/etc/b.conf\x00-p/srv/\x00",
			want: LaunchArgs{Binary: "/usr/sbin/nginx", Conf: "/etc/b.conf", Prefix: "/srv/"},
			ok:   true,
		},
		{
			name: "worker process title",
			raw:  "nginx: worker process\x00",
		},
		{
			// a stale pid file now naming another process
			name: "not nginx",
			raw:  "/usr/sbin/sshd\x00-D\x00",
		},
		{
			name: "empty",
			raw:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseProcCmdline([]byte(tt.raw))
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseBuildInfo(t *testing.T) {
	data, err := os.ReadFile("../testdata/nginx/rhel9-nginx-V.txt")
	require.NoError(t, err)
	b, ok := ParseBuildInfo(string(data))
	require.True(t, ok)
	assert.Equal(t, BuildInfo{Prefix: "/usr/share/nginx", ConfPath: "/etc/nginx/nginx.conf", PidPath: "/run/nginx.pid"}, b)

	// a source build with no path options gets nginx's auto/options defaults
	b, ok = ParseBuildInfo("nginx version: nginx/1.27.0\nbuilt by gcc 12.2.0\nconfigure arguments: --with-http_ssl_module\n")
	require.True(t, ok)
	assert.Equal(t, BuildInfo{Prefix: "/usr/local/nginx/", ConfPath: "conf/nginx.conf", PidPath: "logs/nginx.pid"}, b)

	// a shell error is not nginx -V output
	_, ok = ParseBuildInfo("sh: 1: nginx: not found\n")
	assert.False(t, ok)
}

func TestConfFile(t *testing.T) {
	distro := BuildInfo{Prefix: "/usr/share/nginx", ConfPath: "/etc/nginx/nginx.conf"}
	source := BuildInfo{Prefix: "/usr/local/nginx/", ConfPath: "conf/nginx.conf"}

	assert.Equal(t, "/etc/nginx/nginx.conf", ConfFile(LaunchArgs{}, distro))
	assert.Equal(t, "/etc/nginx-alt/nginx.conf", ConfFile(LaunchArgs{Conf: "/etc/nginx-alt/nginx.conf"}, distro))
	// a relative -c resolves against -p
	assert.Equal(t, "/srv/nginx/conf/site.conf", ConfFile(LaunchArgs{Conf: "conf/site.conf", Prefix: "/srv/nginx/"}, distro))
	// a relative -c without -p resolves against the build's prefix
	assert.Equal(t, "/usr/share/nginx/site.conf", ConfFile(LaunchArgs{Conf: "site.conf"}, distro))
	// -p moves a relative build conf path, but not an absolute one
	assert.Equal(t, "/usr/local/nginx/conf/nginx.conf", ConfFile(LaunchArgs{}, source))
	assert.Equal(t, "/opt/web/conf/nginx.conf", ConfFile(LaunchArgs{Prefix: "/opt/web"}, source))
	assert.Equal(t, "/etc/nginx/nginx.conf", ConfFile(LaunchArgs{Prefix: "/opt/web"}, distro))
}
