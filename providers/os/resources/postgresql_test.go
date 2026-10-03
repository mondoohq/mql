// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/postgresql"
	"go.mondoo.com/mql/utils/syncx"
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

// findPg runs findPostgresqlConfigFile on a filesystem that cannot refuse.
func findPg(t *testing.T, fs afero.Fs, name string) string {
	t.Helper()
	p, err := findPostgresqlConfigFile(fs, name)
	require.NoError(t, err)
	return p
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
			findPg(t, fs, "postgresql.conf"))
	})

	t.Run("rhel layout", func(t *testing.T) {
		fs := pgFs(t, "/var/lib/pgsql/18/data/postgresql.conf")
		assert.Equal(t, "/var/lib/pgsql/18/data/postgresql.conf",
			findPg(t, fs, "postgresql.conf"))
	})

	t.Run("hba and ident use the same search", func(t *testing.T) {
		fs := pgFs(t,
			"/etc/postgresql/18/main/pg_hba.conf",
			"/etc/postgresql/18/main/pg_ident.conf",
		)
		assert.Equal(t, "/etc/postgresql/18/main/pg_hba.conf",
			findPg(t, fs, "pg_hba.conf"))
		assert.Equal(t, "/etc/postgresql/18/main/pg_ident.conf",
			findPg(t, fs, "pg_ident.conf"))
	})
}

// postgresql17-server on FreeBSD 14.5: `service postgresql initdb` creates
// /var/db/postgres/data17 and keeps all three config files in it.
func TestPostgresqlFreeBSDLayout(t *testing.T) {
	fs := pgFs(t,
		"/var/db/postgres/data17/postgresql.conf",
		"/var/db/postgres/data17/pg_hba.conf",
		"/var/db/postgres/data17/pg_ident.conf",
	)
	for _, name := range []string{"postgresql.conf", "pg_hba.conf", "pg_ident.conf"} {
		assert.Equal(t, "/var/db/postgres/data17/"+name, findPg(t, fs, name))
	}

	t.Run("the newest cluster wins, 9.x suffixes rank as major 9", func(t *testing.T) {
		fs := pgFs(t,
			"/var/db/postgres/data96/postgresql.conf",
			"/var/db/postgres/data16/postgresql.conf",
			"/var/db/postgres/data18/postgresql.conf",
		)
		assert.Equal(t, "/var/db/postgres/data18/postgresql.conf",
			findPg(t, fs, "postgresql.conf"))

		fs = pgFs(t,
			"/var/db/postgres/data96/postgresql.conf",
			"/var/db/postgres/data10/postgresql.conf",
		)
		assert.Equal(t, "/var/db/postgres/data10/postgresql.conf",
			findPg(t, fs, "postgresql.conf"))
	})

	t.Run("a directory without a version is not a candidate", func(t *testing.T) {
		fs := pgFs(t, "/var/db/postgres/data_old/postgresql.conf")
		assert.Equal(t, "", findPg(t, fs, "postgresql.conf"))
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
		findPg(t, fs, "postgresql.conf"))
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
		findPg(t, fs, "postgresql.conf"))

	fs = pgFs(t,
		"/var/lib/pgsql/9/data/postgresql.conf",
		"/var/lib/pgsql/13/data/postgresql.conf",
	)
	assert.Equal(t, "/var/lib/pgsql/13/data/postgresql.conf",
		findPg(t, fs, "postgresql.conf"))
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
			findPg(t, fs, "postgresql.conf"))
	})

	t.Run("never offered as a candidate", func(t *testing.T) {
		fs := pgFs(t, "/etc/postgresql/backup/main/postgresql.conf")
		assert.Equal(t, "", findPg(t, fs, "postgresql.conf"))
		assert.NotContains(t, postgresqlConfigSearchPaths(fs, "postgresql.conf"),
			"/etc/postgresql/backup/main/postgresql.conf")
	})
}

// Debian names a cluster at creation (pg_createcluster 15 prod) or later
// (pg_renamecluster 15 main prod, Debian 12 with PostgreSQL 15), and its
// config then lives in /etc/postgresql/15/prod. Looking only for "main" found
// nothing, so every postgresql.* field was null and hba rules were empty:
// rules.none(authMethod == "trust") passed. Fails if the search only globs
// the "main" cluster.
func TestPostgresqlFindsDebianClusterNotNamedMain(t *testing.T) {
	t.Run("a renamed cluster is found", func(t *testing.T) {
		fs := pgFs(t,
			"/etc/postgresql/15/prod/postgresql.conf",
			"/etc/postgresql/15/prod/pg_hba.conf",
			"/etc/postgresql/15/prod/pg_ident.conf",
		)
		for _, name := range []string{"postgresql.conf", "pg_hba.conf", "pg_ident.conf"} {
			assert.Equal(t, "/etc/postgresql/15/prod/"+name, findPg(t, fs, name))
		}
	})

	// A "main" cluster keeps winning over other clusters, of any version, so
	// a host that resolved to 15/main before still does. Fails if the other
	// clusters are merged into the main group's version ranking.
	t.Run("main still wins", func(t *testing.T) {
		fs := pgFs(t,
			"/etc/postgresql/15/main/postgresql.conf",
			"/etc/postgresql/15/second/postgresql.conf",
			"/etc/postgresql/18/second/postgresql.conf",
		)
		assert.Equal(t, "/etc/postgresql/15/main/postgresql.conf",
			findPg(t, fs, "postgresql.conf"))
	})

	// Without a main cluster: highest version first, then cluster name.
	// Fails if the other clusters are not ranked by version, or if a
	// directory that is not a version is offered.
	t.Run("other clusters by version then name", func(t *testing.T) {
		fs := pgFs(t,
			"/etc/postgresql/15/zeta/postgresql.conf",
			"/etc/postgresql/15/alpha/postgresql.conf",
			"/etc/postgresql/16/prod/postgresql.conf",
			"/etc/postgresql/16/beta/postgresql.conf",
			"/etc/postgresql/backup/prod/postgresql.conf",
		)
		paths := postgresqlConfigSearchPaths(fs, "postgresql.conf")
		assert.Equal(t, []string{
			"/etc/postgresql/16/beta/postgresql.conf",
			"/etc/postgresql/16/prod/postgresql.conf",
			"/etc/postgresql/15/alpha/postgresql.conf",
			"/etc/postgresql/15/zeta/postgresql.conf",
		}, paths[:4])
		assert.NotContains(t, paths, "/etc/postgresql/backup/prod/postgresql.conf")
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
			assert.Equal(t, p, findPg(t, pgFs(t, p), "postgresql.conf"))
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

// Ubuntu 16.04 ships PostgreSQL 9.5 in /etc/postgresql/9.5/main. Before
// PostgreSQL 10 the major version had two parts, and an integer-only parse
// of the directory name skipped it, so every postgresql resource read empty
// on that host. Fails if postgresqlVersionRank rejects dotted versions.
func TestPostgresqlFindsPre10Layout(t *testing.T) {
	for _, name := range []string{"postgresql.conf", "pg_hba.conf", "pg_ident.conf"} {
		fs := pgFs(t, "/etc/postgresql/9.5/main/"+name)
		assert.Equal(t, "/etc/postgresql/9.5/main/"+name, findPg(t, fs, name))
	}

	fs := pgFs(t, "/var/lib/pgsql/9.6/data/postgresql.conf")
	assert.Equal(t, "/var/lib/pgsql/9.6/data/postgresql.conf",
		findPg(t, fs, "postgresql.conf"))
}

// Side-by-side clusters across the 9.x/10 boundary: 9.6 is newer than 9.5,
// and 10 is newer than both.
func TestPostgresqlPre10VersionOrdering(t *testing.T) {
	fs := pgFs(t,
		"/etc/postgresql/9.5/main/postgresql.conf",
		"/etc/postgresql/9.6/main/postgresql.conf",
	)
	assert.Equal(t, "/etc/postgresql/9.6/main/postgresql.conf",
		findPg(t, fs, "postgresql.conf"))

	fs = pgFs(t,
		"/etc/postgresql/9.6/main/postgresql.conf",
		"/etc/postgresql/10/main/postgresql.conf",
	)
	assert.Equal(t, "/etc/postgresql/10/main/postgresql.conf",
		findPg(t, fs, "postgresql.conf"))
}

func TestPostgresqlVersionRank(t *testing.T) {
	for _, tc := range []struct {
		in   string
		rank int
		ok   bool
	}{
		{"18", 1800, true},
		{"9.5", 905, true},
		{"9.6", 906, true},
		{"backup", 0, false},
		{"9.", 0, false},
		{".5", 0, false},
		{"9.5.1", 0, false},
		{"0", 0, false},
	} {
		rank, ok := postgresqlVersionRank(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.rank, rank, tc.in)
	}
}

// With no pg_hba.conf or pg_ident.conf found, rules and mappings are null.
// An empty list made `postgresql.hba.rules.none(authMethod == "trust")`
// pass on a host nothing was read from. Fails if rules()/mappings() go back
// to returning an empty list for a nil file.
func TestPostgresqlHbaIdentNoFileIsNull(t *testing.T) {
	hba := &mqlPostgresqlHba{}
	rules, err := hba.rules(nil)
	require.NoError(t, err)
	assert.Nil(t, rules)
	assert.True(t, hba.Rules.State&plugin.StateIsNull != 0, "rules must be null, not []")

	ident := &mqlPostgresqlIdent{}
	mappings, err := ident.mappings(nil)
	require.NoError(t, err)
	assert.Nil(t, mappings)
	assert.True(t, ident.Mappings.State&plugin.StateIsNull != 0, "mappings must be null, not []")
}

// An explicit path that points nowhere is the same absence as no file found:
// null, not an error and not an empty list.
func TestPostgresqlHbaIdentMissingExplicitPathIsNull(t *testing.T) {
	missing := func() *mqlFile {
		f := &mqlFile{}
		f.Path = plugin.TValue[string]{Data: "/etc/postgresql/nope/pg_hba.conf", State: plugin.StateIsSet}
		f.Exists = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
		return f
	}

	hba := &mqlPostgresqlHba{}
	rules, err := hba.rules(missing())
	require.NoError(t, err)
	assert.Nil(t, rules)
	assert.True(t, hba.Rules.State&plugin.StateIsNull != 0, "rules must be null")

	ident := &mqlPostgresqlIdent{}
	mappings, err := ident.mappings(missing())
	require.NoError(t, err)
	assert.Nil(t, mappings)
	assert.True(t, ident.Mappings.State&plugin.StateIsNull != 0, "mappings must be null")
}

// refusingFs answers EACCES for every path under denied, the way stat does
// for the scanning user when a parent directory is 0700 postgres (RHEL's
// /var/lib/pgsql).
type refusingFs struct {
	afero.Fs
	denied string
}

func (r refusingFs) Stat(name string) (os.FileInfo, error) {
	if strings.HasPrefix(name, r.denied+"/") {
		return nil, &os.PathError{Op: "stat", Path: name, Err: syscall.EACCES}
	}
	return r.Fs.Stat(name)
}

func pgStructuredErrors(t *testing.T) {
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
}

// A non-root scan of a RHEL host cannot stat anything under /var/lib/pgsql.
// That is a refusal, not a host without PostgreSQL: reading it as absent made
// every postgresql.* field null and pg_hba rules empty. Fails if the walk
// skips a refused candidate under structured errors.
func TestPostgresqlRefusedCandidateIsAnError(t *testing.T) {
	fs := refusingFs{Fs: pgFs(t, "/var/lib/pgsql/data/postgresql.conf"), denied: "/var/lib/pgsql"}

	p, err := findPostgresqlConfigFile(fs, "postgresql.conf")
	require.NoError(t, err, "v13 skips a refused candidate")
	assert.Equal(t, "", p)

	pgStructuredErrors(t)
	_, err = findPostgresqlConfigFile(fs, "postgresql.conf")
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrForbidden)
	assert.ErrorIs(t, err, os.ErrPermission)
}

// A file found before the refused candidate still wins, so a Debian host
// whose config is world-readable under /etc never hits the refusal.
func TestPostgresqlRefusalOnlyWhenReached(t *testing.T) {
	pgStructuredErrors(t)
	fs := refusingFs{Fs: pgFs(t, "/etc/postgresql/16/main/postgresql.conf"), denied: "/var/lib/postgresql"}
	p, err := findPostgresqlConfigFile(fs, "postgresql.conf", "/var/lib/postgresql/16/main/postgresql.conf")
	require.Error(t, err, "a preferred candidate is probed first")
	assert.Equal(t, "", p)

	p, err = findPostgresqlConfigFile(fs, "postgresql.conf")
	require.NoError(t, err)
	assert.Equal(t, "/etc/postgresql/16/main/postgresql.conf", p)
}

// A data directory relocated with a systemd drop-in (Environment=PGDATA=...)
// is probed before the well-known paths, so a stale default cluster does not
// win. Fails if preferred candidates are appended instead of prepended.
func TestPostgresqlPreferredCandidateWins(t *testing.T) {
	fs := pgFs(t, "/var/lib/pgsql/data/postgresql.conf", "/srv/pgdata/postgresql.conf")
	p, err := findPostgresqlConfigFile(fs, "postgresql.conf", "/srv/pgdata/postgresql.conf")
	require.NoError(t, err)
	assert.Equal(t, "/srv/pgdata/postgresql.conf", p)

	// A preferred candidate that is not there falls through.
	p, err = findPostgresqlConfigFile(fs, "postgresql.conf", "/srv/gone/postgresql.conf")
	require.NoError(t, err)
	assert.Equal(t, "/var/lib/pgsql/data/postgresql.conf", p)
}

// Running postmasters come first, then systemd units, each in the order the
// well-known search paths give them. Fails if the ranking is dropped (the
// PGDG unit would then win over the distro default on a host with both).
func TestPostgresqlPreferredConfigsOrder(t *testing.T) {
	fs := pgFs(t,
		"/etc/postgresql/14/main/postgresql.conf",
		"/etc/postgresql/16/main/postgresql.conf",
		"/var/lib/pgsql/17/data/postgresql.conf",
	)
	running := []postgresql.Instance{
		{DataDir: "/srv/other"},
		{DataDir: "/var/lib/postgresql/14/main", Settings: map[string]string{"config_file": "/etc/postgresql/14/main/postgresql.conf"}},
		{DataDir: "/var/lib/postgresql/16/main", Settings: map[string]string{"config_file": "/etc/postgresql/16/main/postgresql.conf"}},
	}
	// systemctl lists unit files by name, so PGDG's postgresql-17.service
	// comes before the distro's postgresql.service.
	units := []postgresql.Instance{
		{DataDir: "/srv/pgdata"},
		{DataDir: "/var/lib/pgsql/17/data"},
		{DataDir: "/var/lib/pgsql/data"},
	}
	assert.Equal(t, []string{
		"/etc/postgresql/16/main/postgresql.conf",
		"/etc/postgresql/14/main/postgresql.conf",
		"/srv/other/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/pgsql/17/data/postgresql.conf",
		"/srv/pgdata/postgresql.conf",
	}, postgresqlPreferredConfigs(fs, running, units))
}

func TestPostgresqlHomes(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	assert.Nil(t, postgresqlHomes(afs), "no /etc/passwd")

	// SLES 15 SP7
	require.NoError(t, afs.WriteFile("/etc/passwd", []byte("root:x:0:0:root:/root:/bin/bash\n"+
		"postgresql:x:473:473:not the server account:/srv/other:/bin/false\n"+
		"postgres:x:472:472:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n"), 0o644))
	assert.Equal(t, map[string]string{"postgres": "/var/lib/pgsql"}, postgresqlHomes(afs))
}

func pgAutoConfRuntime(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()
	data := &mock.TomlData{Files: map[string]*mock.MockFileData{}}
	for p, c := range files {
		data.Files[p] = &mock.MockFileData{Path: p, Content: c, StatData: mock.FileInfo{Mode: 0o644}}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux"}}}, mock.WithData(data))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// Ubuntu 24.04, PostgreSQL 18: ALTER SYSTEM SET ssl = off and
// password_encryption = md5, then pg_reload_conf(). The server runs with ssl
// off and md5 (pg_settings source "configuration file",
// sourcefile postgresql.auto.conf), while postgresql.conf still says ssl = on.
func TestPostgresqlConfAppliesAutoConf(t *testing.T) {
	runtime := pgAutoConfRuntime(t, map[string]string{
		"/etc/postgresql/18/main/postgresql.conf":          "data_directory = '/var/lib/postgresql/18/main'\nssl = on\npassword_encryption = scram-sha-256\nport = 5443\n",
		"/var/lib/postgresql/18/main/postgresql.auto.conf": "# Do not edit this file manually!\n# It will be overwritten by the ALTER SYSTEM command.\nssl = 'off'\npassword_encryption = 'md5'\n",
	})
	raw, err := NewResource(runtime, "postgresql.conf", map[string]*llx.RawData{"path": llx.StringData("/etc/postgresql/18/main/postgresql.conf")})
	require.NoError(t, err)
	conf := raw.(*mqlPostgresqlConf)

	ssl := conf.GetSslEnabled()
	require.NoError(t, ssl.Error)
	assert.False(t, ssl.Data, "ALTER SYSTEM SET ssl = off wins over postgresql.conf")
	assert.Equal(t, "md5", conf.GetPasswordEncryption().Data)
	assert.Equal(t, int64(5443), conf.GetPort().Data, "settings auto.conf does not set stay")

	files := conf.GetFiles()
	require.NoError(t, files.Error)
	var paths []string
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.Equal(t, []string{"/etc/postgresql/18/main/postgresql.conf", "/var/lib/postgresql/18/main/postgresql.auto.conf"}, paths)
}

// RHEL keeps postgresql.conf in the data directory and sets no
// data_directory, so postgresql.auto.conf sits next to it.
func TestPostgresqlConfAutoConfNextToConfWithoutDataDirectory(t *testing.T) {
	runtime := pgAutoConfRuntime(t, map[string]string{
		"/var/lib/pgsql/data/postgresql.conf":      "ssl = on\n",
		"/var/lib/pgsql/data/postgresql.auto.conf": "ssl = 'off'\n",
	})
	raw, err := NewResource(runtime, "postgresql.conf", map[string]*llx.RawData{"path": llx.StringData("/var/lib/pgsql/data/postgresql.conf")})
	require.NoError(t, err)
	assert.False(t, raw.(*mqlPostgresqlConf).GetSslEnabled().Data)
}

// No ALTER SYSTEM ever ran: there is no postgresql.auto.conf, and nothing
// changes.
func TestPostgresqlConfWithoutAutoConf(t *testing.T) {
	runtime := pgAutoConfRuntime(t, map[string]string{
		"/var/lib/pgsql/data/postgresql.conf": "ssl = on\n",
	})
	raw, err := NewResource(runtime, "postgresql.conf", map[string]*llx.RawData{"path": llx.StringData("/var/lib/pgsql/data/postgresql.conf")})
	require.NoError(t, err)
	conf := raw.(*mqlPostgresqlConf)
	ssl := conf.GetSslEnabled()
	require.NoError(t, ssl.Error)
	assert.True(t, ssl.Data)
	assert.Len(t, conf.GetFiles().Data, 1)
}
