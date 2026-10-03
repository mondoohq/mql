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

// postgres:13-alpine started with
// `-c log_connections=on -c password_encryption=md5 -c listen_addresses=127.0.0.1`:
// the postmaster is pid 1 without -D, its data directory comes from PGDATA,
// and the file leaves all three settings at their defaults or '*'.
var pgImageFiles = map[string]string{
	"/proc/1/cmdline":  "postgres\x00-c\x00log_connections=on\x00-c\x00password_encryption=md5\x00-c\x00listen_addresses=127.0.0.1\x00",
	"/proc/1/stat":     "1 (postgres) S 0 1 1 0 -1",
	"/proc/55/cmdline": "postgres: checkpointer   \x00\x00\x00",
	"/proc/55/stat":    "55 (postgres) S 1 55 55 0 -1",
	"/var/lib/postgresql/data/postgresql.conf": "listen_addresses = '*'\n#password_encryption = md5\n#log_connections = off\n",
	"/var/lib/postgresql/data/PG_VERSION":      "13\n",
}

const pgPostmasterPid = "1\n/var/lib/postgresql/data\n1791032192\n5432\n/var/run/postgresql\n127.0.0.1\n   278037         5\nready   \n"

var pgrepPostgres = map[string]*mock.Command{"pgrep -x 'postgres|postmaster'": {Stdout: "1\n55\n"}}

func pgConfOf(t *testing.T, rt *plugin.Runtime) *mqlPostgresqlConf {
	t.Helper()
	res, err := NewResource(rt, "postgresql.conf", nil)
	require.NoError(t, err)
	conf := res.(*mqlPostgresqlConf)
	require.NoError(t, conf.GetFile().Error)
	require.NotNil(t, conf.GetFile().Data)
	require.Equal(t, "/var/lib/postgresql/data/postgresql.conf", conf.GetFile().Data.Path.Data)
	return conf
}

func assertPgCommandLine(t *testing.T, conf *mqlPostgresqlConf) {
	t.Helper()
	assert.True(t, conf.GetLogConnections().Data)
	assert.Equal(t, "md5", conf.GetPasswordEncryption().Data)
	assert.Equal(t, []any{"127.0.0.1"}, conf.GetListenAddresses().Data)
	assert.Equal(t, "on", conf.GetParams().Data["log_connections"])
}

func TestPostgresqlConfCommandLineOverrides(t *testing.T) {
	t.Run("root without ptrace: postmaster.pid ties the process to the data directory", func(t *testing.T) {
		files := mergeFiles(pgImageFiles, map[string]string{"/var/lib/postgresql/data/postmaster.pid": pgPostmasterPid})
		assertPgCommandLine(t, pgConfOf(t, newLaunchRuntime(t, files, pgrepPostgres, nil)))
	})

	t.Run("the server's account: PGDATA from its environment", func(t *testing.T) {
		files := mergeFiles(pgImageFiles, map[string]string{"/proc/1/environ": "HOSTNAME=x\x00PGDATA=/var/lib/postgresql/data\x00PG_MAJOR=13\x00"})
		assertPgCommandLine(t, pgConfOf(t, newLaunchRuntime(t, files, pgrepPostgres, nil)))
	})

	t.Run("a postmaster.pid of another process applies nothing", func(t *testing.T) {
		files := mergeFiles(pgImageFiles, map[string]string{"/var/lib/postgresql/data/postmaster.pid": "4242\n/var/lib/postgresql/data\n"})
		conf := pgConfOf(t, newLaunchRuntime(t, files, pgrepPostgres, nil))
		assert.False(t, conf.GetLogConnections().Data)
		assert.Equal(t, []any{"*"}, conf.GetListenAddresses().Data)
	})

	t.Run("the image's Cmd and PGDATA", func(t *testing.T) {
		image := &tar.ImageConfig{
			Entrypoint: []string{"docker-entrypoint.sh"},
			Cmd:        []string{"postgres", "-c", "log_connections=on", "-c", "password_encryption=md5", "-c", "listen_addresses=127.0.0.1"},
			Env:        []string{"PATH=/usr/local/bin", "PGDATA=/var/lib/postgresql/data"},
		}
		files := map[string]string{"/var/lib/postgresql/data/postgresql.conf": pgImageFiles["/var/lib/postgresql/data/postgresql.conf"]}
		assertPgCommandLine(t, pgConfOf(t, newLaunchRuntime(t, files, nil, image)))
	})
}
