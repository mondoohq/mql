// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCassandraLauncherVars(t *testing.T) {
	fsWith := func(dirs ...string) *afero.Afero {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		for _, d := range dirs {
			require.NoError(t, afs.MkdirAll(d, 0o755))
		}
		return afs
	}

	for _, tc := range []struct {
		name    string
		afs     *afero.Afero
		envPath string
		want    map[string]string
	}{
		{"Debian package", fsWith("/usr/share/cassandra/lib"), "/etc/cassandra/cassandra-env.sh",
			map[string]string{"CASSANDRA_HOME": "/usr/share/cassandra", "CASSANDRA_CONF": "/etc/cassandra"}},
		{"RPM conf subdirectory", fsWith("/usr/share/cassandra/lib"), "/etc/cassandra/conf/cassandra-env.sh",
			map[string]string{"CASSANDRA_HOME": "/usr/share/cassandra", "CASSANDRA_CONF": "/etc/cassandra/conf"}},
		{"container image", fsWith("/opt/cassandra/lib"), "/etc/cassandra/cassandra-env.sh",
			map[string]string{"CASSANDRA_HOME": "/opt/cassandra", "CASSANDRA_CONF": "/etc/cassandra"}},
		{"tarball", fsWith(), "/opt/apache-cassandra-5.0.9/conf/cassandra-env.sh",
			map[string]string{"CASSANDRA_HOME": "/opt/apache-cassandra-5.0.9", "CASSANDRA_CONF": "/opt/apache-cassandra-5.0.9/conf"}},
		{"/etc without a known home", fsWith(), "/etc/cassandra/cassandra-env.sh",
			map[string]string{"CASSANDRA_CONF": "/etc/cassandra"}},
		{"Homebrew", fsWith("/usr/share/cassandra/lib"), "/opt/homebrew/etc/cassandra/cassandra-env.sh",
			map[string]string{"CASSANDRA_CONF": "/opt/homebrew/etc/cassandra"}},
		{"no path", fsWith(), "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cassandraLauncherVars(tc.afs, tc.envPath))
		})
	}
}
