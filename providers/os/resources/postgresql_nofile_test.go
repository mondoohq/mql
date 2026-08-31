// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// confNotFound builds the state file() leaves behind when no postgresql.conf
// exists anywhere on the host: File marked set+null.
func confNotFound() *mqlPostgresqlConf {
	s := &mqlPostgresqlConf{}
	s.File = plugin.TValue[*mqlFile]{State: plugin.StateIsSet | plugin.StateIsNull}
	return s
}

// confPresent builds the state for a config file that exists but omits every
// directive. PostgreSQL's documented defaults DO apply here, so the accessors
// must keep returning them.
func confPresent() *mqlPostgresqlConf {
	s := &mqlPostgresqlConf{}
	s.File = plugin.TValue[*mqlFile]{Data: &mqlFile{}, State: plugin.StateIsSet}
	return s
}

// With no config file at all there is nothing to default from. Reporting
// port 5432 / listenAddresses ["localhost"] / sslEnabled false describes a
// posture nobody configured, and lets a "does not listen on *" assertion pass
// against a host where PostgreSQL was never set up.
func TestPostgresqlConfNoFileReturnsNull(t *testing.T) {
	empty := map[string]any{}

	t.Run("port", func(t *testing.T) {
		s := confNotFound()
		v, err := s.port(empty)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), v)
		assert.True(t, s.Port.State&plugin.StateIsNull != 0, "port must be null, not 5432")
	})

	t.Run("listenAddresses", func(t *testing.T) {
		s := confNotFound()
		v, err := s.listenAddresses(empty)
		assert.NoError(t, err)
		assert.Nil(t, v)
		assert.True(t, s.ListenAddresses.State&plugin.StateIsNull != 0,
			"listenAddresses must be null, not [localhost]")
	})

	t.Run("sslEnabled", func(t *testing.T) {
		s := confNotFound()
		v, err := s.sslEnabled(empty)
		assert.NoError(t, err)
		assert.False(t, v)
		assert.True(t, s.SslEnabled.State&plugin.StateIsNull != 0,
			"sslEnabled must be null; false reads as a real finding")
	})

	t.Run("loggingCollector", func(t *testing.T) {
		s := confNotFound()
		_, err := s.loggingCollector(empty)
		assert.NoError(t, err)
		assert.True(t, s.LoggingCollector.State&plugin.StateIsNull != 0)
	})

	t.Run("logConnections", func(t *testing.T) {
		s := confNotFound()
		_, err := s.logConnections(empty)
		assert.NoError(t, err)
		assert.True(t, s.LogConnections.State&plugin.StateIsNull != 0)
	})

	t.Run("dataDirectory", func(t *testing.T) {
		s := confNotFound()
		v, err := s.dataDirectory(empty)
		assert.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, s.DataDirectory.State&plugin.StateIsNull != 0)
	})

	t.Run("sharedPreloadLibraries", func(t *testing.T) {
		s := confNotFound()
		v, err := s.sharedPreloadLibraries(empty)
		assert.NoError(t, err)
		assert.Nil(t, v)
		assert.True(t, s.SharedPreloadLibraries.State&plugin.StateIsNull != 0)
	})
}

// The documented defaults are still correct when the file exists and simply
// does not mention the directive. This is the behaviour the guard must not
// break.
func TestPostgresqlConfPresentButEmptyKeepsDefaults(t *testing.T) {
	empty := map[string]any{}

	s := confPresent()
	port, err := s.port(empty)
	assert.NoError(t, err)
	assert.Equal(t, int64(5432), port, "a present file with no port directive still defaults")
	assert.True(t, s.Port.State&plugin.StateIsNull == 0, "and is not null")

	s = confPresent()
	addrs, err := s.listenAddresses(empty)
	assert.NoError(t, err)
	assert.Equal(t, []any{"localhost"}, addrs)

	s = confPresent()
	ssl, err := s.sslEnabled(empty)
	assert.NoError(t, err)
	assert.False(t, ssl, "ssl is genuinely off when the file omits it")
	assert.True(t, s.SslEnabled.State&plugin.StateIsNull == 0)
}

// A directive that IS present must win regardless.
func TestPostgresqlConfPresentWithValues(t *testing.T) {
	s := confPresent()
	port, err := s.port(map[string]any{"port": "6543"})
	assert.NoError(t, err)
	assert.Equal(t, int64(6543), port)

	s = confPresent()
	ssl, err := s.sslEnabled(map[string]any{"ssl": "on"})
	assert.NoError(t, err)
	assert.True(t, ssl)
}

// pgFs builds an in-memory filesystem holding exactly the given config files.
func pgFs(t *testing.T, paths ...string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for _, p := range paths {
		require.NoError(t, afero.WriteFile(fs, p, []byte("# test\n"), 0o644))
	}
	return fs
}

// The search path used to enumerate majors by hand and stopped at 17, so a
// PostgreSQL 18 host resolved no config at all and every directive read as
// unset — with no error to say why. 19 lands around Sept 2026 and would have
// broken it again, which is why the version-stamped groups are globbed.
func TestPostgresqlFindsCurrentMajor(t *testing.T) {
	t.Run("debian layout", func(t *testing.T) {
		fs := pgFs(t, "/etc/postgresql/18/main/postgresql.conf")
		assert.Equal(t, "/etc/postgresql/18/main/postgresql.conf",
			findPostgresqlConfigFile(fs, "postgresql.conf"))
	})

	t.Run("rhel layout", func(t *testing.T) {
		fs := pgFs(t, "/var/lib/pgsql/18/data/postgresql.conf")
		assert.Equal(t, "/var/lib/pgsql/18/data/postgresql.conf",
			findPostgresqlConfigFile(fs, "postgresql.conf"))
	})

	t.Run("hba and ident use the same search", func(t *testing.T) {
		fs := pgFs(t,
			"/etc/postgresql/18/main/pg_hba.conf",
			"/etc/postgresql/18/main/pg_ident.conf",
		)
		assert.Equal(t, "/etc/postgresql/18/main/pg_hba.conf",
			findPostgresqlConfigFile(fs, "pg_hba.conf"))
		assert.Equal(t, "/etc/postgresql/18/main/pg_ident.conf",
			findPostgresqlConfigFile(fs, "pg_ident.conf"))
	})
}

// A host carrying several clusters resolves to the newest, the way the old
// descending enumeration did.
func TestPostgresqlPrefersHighestMajor(t *testing.T) {
	fs := pgFs(t,
		"/etc/postgresql/17/main/postgresql.conf",
		"/etc/postgresql/18/main/postgresql.conf",
	)
	assert.Equal(t, "/etc/postgresql/18/main/postgresql.conf",
		findPostgresqlConfigFile(fs, "postgresql.conf"))
}

// Glob results arrive in lexicographic order, where "9" sorts above "17".
// /etc/postgresql/9/main still exists on long-lived hosts, so the ordering
// must compare majors as integers. This test fails if anyone sorts strings.
func TestPostgresqlMajorSortIsNumericNotLexical(t *testing.T) {
	fs := pgFs(t,
		"/etc/postgresql/9/main/postgresql.conf",
		"/etc/postgresql/17/main/postgresql.conf",
	)
	assert.Equal(t, "/etc/postgresql/17/main/postgresql.conf",
		findPostgresqlConfigFile(fs, "postgresql.conf"))

	fs = pgFs(t,
		"/var/lib/pgsql/9/data/postgresql.conf",
		"/var/lib/pgsql/13/data/postgresql.conf",
	)
	assert.Equal(t, "/var/lib/pgsql/13/data/postgresql.conf",
		findPostgresqlConfigFile(fs, "postgresql.conf"))
}

// An operator's backup copy under /etc/postgresql has no integer major.
// It must be skipped, not parsed as major 0 and not blow up the search.
func TestPostgresqlNonNumericDirectoryIsSkipped(t *testing.T) {
	t.Run("skipped in favour of a real cluster", func(t *testing.T) {
		fs := pgFs(t,
			"/etc/postgresql/backup/main/postgresql.conf",
			"/etc/postgresql/16/main/postgresql.conf",
		)
		assert.Equal(t, "/etc/postgresql/16/main/postgresql.conf",
			findPostgresqlConfigFile(fs, "postgresql.conf"))
	})

	t.Run("never offered as a candidate", func(t *testing.T) {
		fs := pgFs(t, "/etc/postgresql/backup/main/postgresql.conf")
		assert.Equal(t, "", findPostgresqlConfigFile(fs, "postgresql.conf"))
		assert.NotContains(t, postgresqlConfigSearchPaths(fs, "postgresql.conf"),
			"/etc/postgresql/backup/main/postgresql.conf")
	})
}

// The version-less layouts — container images, an initdb default, homebrew —
// are what the glob does NOT cover, and they still have to resolve.
func TestPostgresqlVersionlessPathsStillResolve(t *testing.T) {
	for _, p := range []string{
		"/var/lib/postgresql/data/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/usr/local/var/postgres/postgresql.conf",
		"/usr/local/pgsql/data/postgresql.conf",
	} {
		t.Run(p, func(t *testing.T) {
			assert.Equal(t, p, findPostgresqlConfigFile(pgFs(t, p), "postgresql.conf"))
		})
	}
}

// The version-stamped groups keep the precedence the flat list gave them:
// /etc/postgresql beats the version-less paths, which beat /var/lib/pgsql/<N>.
func TestPostgresqlSearchOrderIsPreserved(t *testing.T) {
	fs := pgFs(t,
		"/etc/postgresql/16/main/postgresql.conf",
		"/var/lib/postgresql/data/postgresql.conf",
		"/var/lib/pgsql/18/data/postgresql.conf",
		"/usr/local/pgsql/data/postgresql.conf",
	)
	assert.Equal(t, []string{
		"/etc/postgresql/16/main/postgresql.conf",
		"/var/lib/postgresql/data/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/pgsql/18/data/postgresql.conf",
		"/usr/local/var/postgres/postgresql.conf",
		"/usr/local/pgsql/data/postgresql.conf",
	}, postgresqlConfigSearchPaths(fs, "postgresql.conf"))
}

// A filesystem that cannot be globbed must degrade to the version-less paths
// rather than panicking, matching what the hardcoded list did.
func TestPostgresqlNilFilesystemDoesNotPanic(t *testing.T) {
	assert.Equal(t, []string{
		"/var/lib/postgresql/data/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/usr/local/var/postgres/postgresql.conf",
		"/usr/local/pgsql/data/postgresql.conf",
	}, postgresqlConfigSearchPaths(nil, "postgresql.conf"))
}
