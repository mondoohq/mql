// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
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
			assert.Equal(t, tt.want, mongodConfigPath(afs))
		})
	}
}
