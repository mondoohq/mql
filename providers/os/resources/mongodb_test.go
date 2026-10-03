// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rpmMongodUnit is the [Service] section of mongod.service from MongoDB's rpm
// packages (mongodb-org-server 8.0 on SLES 15).
const rpmMongodUnit = `[Service]
User=mongod
Group=mongod
Environment="OPTIONS=-f /etc/mongod.conf"
Environment="MONGODB_CONFIG_OVERRIDE_NOFORK=1"
Environment="GLIBC_TUNABLES=glibc.pthread.rseq=0"
EnvironmentFile=-/etc/sysconfig/mongod
ExecStart=/usr/bin/mongod $OPTIONS
RuntimeDirectory=mongodb
`

// debMongodUnit is the [Service] section of mongod.service from MongoDB's deb
// packages.
const debMongodUnit = `[Service]
User=mongodb
Group=mongodb
EnvironmentFile=-/etc/default/mongod
Environment="MONGODB_CONFIG_OVERRIDE_NOFORK=1"
ExecStart=/usr/bin/mongod --config /etc/mongod.conf
RuntimeDirectory=mongodb
`

func TestMongodConfigPath(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "rpm unit relocated through /etc/sysconfig/mongod, stopped",
			files: map[string]string{
				"/usr/lib/systemd/system/mongod.service": rpmMongodUnit,
				"/etc/sysconfig/mongod":                  `OPTIONS="-f /etc/mongod-alt.conf"` + "\n",
			},
			want: "/etc/mongod-alt.conf",
		},
		{
			name: "rpm unit without a sysconfig file",
			files: map[string]string{
				"/usr/lib/systemd/system/mongod.service": rpmMongodUnit,
			},
			want: "/etc/mongod.conf",
		},
		{
			// /etc/sysconfig/mongod was edited after mongod started, so the
			// running process is the one to believe
			name: "running process wins over the unit",
			files: map[string]string{
				"/usr/lib/systemd/system/mongod.service":                  rpmMongodUnit,
				"/sys/fs/cgroup/system.slice/mongod.service/cgroup.procs": "21279\n",
				"/proc/21279/cmdline":                                     "/usr/bin/mongod\x00-f\x00/etc/mongod-alt.conf\x00",
			},
			want: "/etc/mongod-alt.conf",
		},
		{
			name: "a pid that is not mongod falls back to the unit",
			files: map[string]string{
				"/usr/lib/systemd/system/mongod.service":                  rpmMongodUnit,
				"/etc/sysconfig/mongod":                                   `OPTIONS="-f /etc/mongod-alt.conf"` + "\n",
				"/sys/fs/cgroup/system.slice/mongod.service/cgroup.procs": "4242\n",
				"/proc/4242/cmdline":                                      "/usr/bin/numactl\x00--interleave=all\x00",
			},
			want: "/etc/mongod-alt.conf",
		},
		{
			name: "deb unit",
			files: map[string]string{
				"/lib/systemd/system/mongod.service": debMongodUnit,
			},
			want: "/etc/mongod.conf",
		},
		{
			name:  "no mongod service",
			files: map[string]string{"/etc/mongod.conf": "net:\n  port: 27017\n"},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			afs := &afero.Afero{Fs: afero.NewMemMapFs()}
			for p, content := range tt.files {
				require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
			}
			got, _, err := mongodConfigPath(afs, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Debian 12, mongod.service stopped and a mongod started by hand with
// `mongod -f /etc/mongod-manual.conf --fork` (bindIpAll, no auth). The server
// listening on 0.0.0.0:27017 is that process; the unit's /etc/mongod.conf
// (127.0.0.1, authorization enabled) describes nothing that runs.
func TestMongodConfigPathProcessOutsideTheUnit(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range map[string]string{
		"/lib/systemd/system/mongod.service": debMongodUnit,
		"/proc/3141/cmdline":                 "/usr/bin/mongod\x00-f\x00/etc/mongod-manual.conf\x00--fork\x00--logpath\x00/tmp/mdb/log\x00",
		"/proc/2718/cmdline":                 "/usr/bin/python3\x00/usr/bin/mongod-helper\x00",
	} {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	got, _, err := mongodConfigPath(afs, []string{"2718", "3141"})
	require.NoError(t, err)
	assert.Equal(t, "/etc/mongod-manual.conf", got)
}

// The service's own process still wins over another mongod on the host.
func TestMongodConfigPathServiceBeatsOtherProcesses(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range map[string]string{
		"/lib/systemd/system/mongod.service":                      debMongodUnit,
		"/sys/fs/cgroup/system.slice/mongod.service/cgroup.procs": "21279\n",
		"/proc/21279/cmdline":                                     "/usr/bin/mongod\x00--config\x00/etc/mongod-alt.conf\x00",
		"/proc/3141/cmdline":                                      "/usr/bin/mongod\x00-f\x00/etc/mongod-manual.conf\x00",
	} {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	got, _, err := mongodConfigPath(afs, []string{"3141", "21279"})
	require.NoError(t, err)
	assert.Equal(t, "/etc/mongod-alt.conf", got)
}

// /proc mounted with hidepid=2: a non-root scan reads the service's pid from
// its cgroup but not the process's command line. Debian 12 then reported the
// unit's /etc/mongod.conf for a server running /etc/mongod-alt.conf. That is a
// refusal, not a server that does not exist.
func TestMongodConfigPathHiddenProcessIsARefusal(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range map[string]string{
		"/lib/systemd/system/mongod.service":                      debMongodUnit,
		"/sys/fs/cgroup/system.slice/mongod.service/cgroup.procs": "21279\n",
		"/proc/mounts": "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0\n",
	} {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	got, _, err := mongodConfigPath(afs, nil)
	require.Error(t, err)
	assert.Equal(t, "/etc/mongod.conf", got, "the unit's file is still what v13 reported")
	assert.True(t, errors.Is(err, fs.ErrNotExist), "the refused read is reported: %v", err)

	// Without hidepid the same missing pid is a process that has exited.
	require.NoError(t, afs.WriteFile("/proc/mounts", []byte("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"), 0o644))
	got, _, err = mongodConfigPath(afs, nil)
	require.NoError(t, err)
	assert.Equal(t, "/etc/mongod.conf", got)
}

func TestProcMountHidesPids(t *testing.T) {
	for opts, want := range map[string]bool{
		"rw,nosuid,nodev,noexec,relatime":                   false,
		"rw,nosuid,nodev,noexec,relatime,hidepid=0":         false,
		"rw,nosuid,nodev,noexec,relatime,hidepid=1":         true,
		"rw,nosuid,nodev,noexec,relatime,hidepid=2":         true,
		"rw,nosuid,nodev,noexec,relatime,hidepid=invisible": true,
		"rw,relatime,gid=1001,hidepid=noaccess":             true,
		"rw,relatime,hidepid=off":                           false,
	} {
		mounts := "sysfs /sys sysfs rw 0 0\nproc /proc proc " + opts + " 0 0\n"
		assert.Equal(t, want, procMountHidesPids(mounts), opts)
	}
	assert.False(t, procMountHidesPids("proc /mnt/chroot/proc proc rw,hidepid=2 0 0\n"), "only /proc counts")
}

// The command line that names the file comes back with it, so its other
// options can override the file: RHEL 9 with
// OPTIONS="-f /etc/mongod.conf --bind_ip_all --port 27018".
func TestMongodConfigPathReturnsTheCommandLine(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range map[string]string{
		"/usr/lib/systemd/system/mongod.service": rpmMongodUnit,
		"/etc/sysconfig/mongod":                  `OPTIONS="-f /etc/mongod.conf --bind_ip_all --port 27018"` + "\n",
	} {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	got, argv, err := mongodConfigPath(afs, nil)
	require.NoError(t, err)
	assert.Equal(t, "/etc/mongod.conf", got)
	assert.Equal(t, []string{"-f", "/etc/mongod.conf", "--bind_ip_all", "--port", "27018"}, argv)
}
