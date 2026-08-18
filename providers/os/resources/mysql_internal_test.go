// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
	"go.mondoo.com/mql/v13/utils/syncx"
)

// mycnfRuntime builds a runtime backed by one of the captured installation
// fixtures under testdata.
func mycnfRuntime(t *testing.T, fixture string) *plugin.Runtime {
	t.Helper()

	fixturePath, err := filepath.Abs(filepath.Join("testdata", fixture))
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "debian",
			Family: []string{"debian", "linux", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func mysqlConf(t *testing.T, fixture string) *mqlMysqlConf {
	t.Helper()
	raw, err := CreateResource(mycnfRuntime(t, fixture), "mysql.conf", nil)
	require.NoError(t, err)
	return raw.(*mqlMysqlConf)
}

func mariadbConf(t *testing.T, fixture string) *mqlMariadbConf {
	t.Helper()
	raw, err := CreateResource(mycnfRuntime(t, fixture), "mariadb.conf", nil)
	require.NoError(t, err)
	return raw.(*mqlMariadbConf)
}

func serverOptions(t *testing.T, conf *mqlMysqlConf) map[string]any {
	t.Helper()
	opts := conf.GetServerOptions()
	require.NoError(t, opts.Error)
	return opts.Data
}

// ---------------------------------------------------------------------------
// the flavor gate
// ---------------------------------------------------------------------------

// mysql.conf must report nothing on a MariaDB host. Every one of these layouts
// puts a readable, parseable option file at a path mysql.conf probes, so
// without the flavor gate each would be reported as a MySQL configuration.
func TestMysqlConf_IsEmptyOnMariadbHosts(t *testing.T) {
	for _, tc := range []struct{ fixture, why string }{
		{"mysql_debian13_mariadb.toml", "/etc/mysql/my.cnf is the same path Ubuntu's MySQL uses"},
		{"mysql_almalinux9_mariadb.toml", "/etc/my.cnf is the same path Oracle's MySQL uses"},
		{"mysql_mariadb114.toml", "/etc/mysql/my.cnf parses cleanly and holds no MariaDB name until expanded"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			conf := mysqlConf(t, tc.fixture)

			file := conf.GetFile()
			require.NoError(t, file.Error)
			assert.Nil(t, file.Data, tc.why)

			// The null file must not cascade into errors on dependent fields.
			opts := conf.GetServerOptions()
			require.NoError(t, opts.Error)
			assert.Empty(t, opts.Data)

			sections := conf.GetSections()
			require.NoError(t, sections.Error)
			assert.Empty(t, sections.Data)
		})
	}
}

// The mirror of the above: mariadb.conf must report nothing on a MySQL host.
func TestMariadbConf_IsEmptyOnMysqlHosts(t *testing.T) {
	for _, fixture := range []string{"mysql_oracle80.toml", "mysql_ubuntu2404.toml"} {
		t.Run(fixture, func(t *testing.T) {
			conf := mariadbConf(t, fixture)

			file := conf.GetFile()
			require.NoError(t, file.Error)
			assert.Nil(t, file.Data)

			opts := conf.GetServerOptions()
			require.NoError(t, opts.Error)
			assert.Empty(t, opts.Data)
		})
	}
}

func TestMysqlConf_ResolvesOnMysqlHosts(t *testing.T) {
	for _, tc := range []struct{ fixture, wantPath string }{
		{"mysql_oracle80.toml", "/etc/my.cnf"},
		{"mysql_ubuntu2404.toml", "/etc/mysql/my.cnf"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			conf := mysqlConf(t, tc.fixture)
			file := conf.GetFile()
			require.NoError(t, file.Error)
			require.NotNil(t, file.Data)
			assert.Equal(t, tc.wantPath, file.Data.Path.Data)
		})
	}
}

func TestMariadbConf_ResolvesOnMariadbHosts(t *testing.T) {
	for _, tc := range []struct{ fixture, wantPath string }{
		{"mysql_debian13_mariadb.toml", "/etc/mysql/my.cnf"},
		{"mysql_almalinux9_mariadb.toml", "/etc/my.cnf"},
		{"mysql_mariadb114.toml", "/etc/mysql/my.cnf"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			conf := mariadbConf(t, tc.fixture)
			file := conf.GetFile()
			require.NoError(t, file.Error)
			require.NotNil(t, file.Data)
			assert.Equal(t, tc.wantPath, file.Data.Path.Data)
		})
	}
}

// Naming a file explicitly bypasses the gate: a caller who says which file to
// read gets that file parsed whichever product it belongs to.
func TestMysqlConf_ExplicitPathBypassesTheGate(t *testing.T) {
	runtime := mycnfRuntime(t, "mysql_debian13_mariadb.toml")
	// path is an init argument rather than a field, so it has to go through
	// NewResource; CreateResource does not run a resource's init.
	raw, err := NewResource(runtime, "mysql.conf", map[string]*llx.RawData{
		"path": llx.StringData("/etc/mysql/mariadb.conf.d/50-server.cnf"),
	})
	require.NoError(t, err)
	conf := raw.(*mqlMysqlConf)

	file := conf.GetFile()
	require.NoError(t, file.Error)
	require.NotNil(t, file.Data)
	assert.Equal(t, "/etc/mysql/mariadb.conf.d/50-server.cnf", file.Data.Path.Data)

	sections := conf.GetSections()
	require.NoError(t, sections.Error)
	assert.NotEmpty(t, sections.Data)
}

// ---------------------------------------------------------------------------
// include expansion and option resolution
// ---------------------------------------------------------------------------

func TestMysqlConf_OracleImageOptions(t *testing.T) {
	conf := mysqlConf(t, "mysql_oracle80.toml")
	opts := serverOptions(t, conf)

	assert.Equal(t, "/var/lib/mysql", opts["datadir"])
	assert.Equal(t, "/var/lib/mysql-files", opts["secure_file_priv"])
	assert.Equal(t, "mysql", opts["user"])

	// skip-name-resolve is written bare, so it resolves to enabled.
	assert.True(t, conf.GetSkipNameResolve().Data)

	client := conf.GetClientOptions()
	require.NoError(t, client.Error)
	assert.Equal(t, "/var/run/mysqld/mysqld.sock", client.Data["socket"])
}

func TestMysqlConf_UbuntuOptionsComeFromTheFragment(t *testing.T) {
	conf := mysqlConf(t, "mysql_ubuntu2404.toml")

	// The root file sets nothing; everything lives in mysql.conf.d/mysqld.cnf.
	opts := serverOptions(t, conf)
	assert.Equal(t, "mysql", opts["user"])
	assert.Equal(t, "127.0.0.1", opts["bind_address"])
	assert.Equal(t, "/var/log/mysql/error.log", opts["log_error"])

	assert.Equal(t, []any{"127.0.0.1"}, conf.GetBindAddress().Data)
	assert.Equal(t, "/var/log/mysql/error.log", conf.GetLogError().Data)

	files := conf.GetFiles()
	require.NoError(t, files.Error)
	paths := []string{}
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.Contains(t, paths, "/etc/mysql/my.cnf")
	assert.Contains(t, paths, "/etc/mysql/mysql.conf.d/mysqld.cnf")
	assert.Contains(t, paths, "/etc/mysql/conf.d/mysqldump.cnf")
}

// MariaDB 11 configures the server under [mariadbd] and ships no [mysqld]
// group, so server scope has to include it or the whole view comes back empty.
func TestMariadbConf_ServerScopeUsesMariadbdGroup(t *testing.T) {
	conf := mariadbConf(t, "mysql_debian13_mariadb.toml")
	opts := conf.GetServerOptions()
	require.NoError(t, opts.Error)

	assert.Equal(t, "127.0.0.1", opts.Data["bind_address"])
	assert.Equal(t, "/run/mysqld/mysqld.pid", opts.Data["pid_file"])
	assert.Equal(t, "/usr", opts.Data["basedir"])
	// [client-server] is server scope on MariaDB, and it is where the
	// packaged socket path lives.
	assert.Equal(t, "/run/mysqld/mysqld.sock", opts.Data["socket"])

	assert.Equal(t, []any{"127.0.0.1"}, conf.GetBindAddress().Data)
	assert.Equal(t, int64(10), conf.GetExpireLogsDays().Data)
}

// Debian's MariaDB packages install one fragment per compression provider, so
// a last-write-wins merge would report one plugin where five are loaded.
func TestMariadbConf_PluginLoadAccumulatesAcrossFragments(t *testing.T) {
	conf := mariadbConf(t, "mysql_debian13_mariadb.toml")
	plugins := conf.GetPluginLoad()
	require.NoError(t, plugins.Error)

	assert.ElementsMatch(t, []any{
		"provider_bzip2", "provider_lz4", "provider_lzma", "provider_lzo", "provider_snappy",
	}, plugins.Data)
}

func TestMariadbConf_GaleraOptionsAreSeparate(t *testing.T) {
	conf := mariadbConf(t, "mysql_debian13_mariadb.toml")

	// The packaged 60-galera.cnf declares [galera] with everything commented
	// out, so the group exists and carries nothing.
	galera := conf.GetGaleraOptions()
	require.NoError(t, galera.Error)
	assert.Empty(t, galera.Data)

	// wsrep settings resolve off the galera group, not off server scope.
	assert.False(t, conf.GetWsrepOn().Data)

	names := []string{}
	sections := conf.GetSections()
	require.NoError(t, sections.Error)
	for _, s := range sections.Data {
		names = append(names, s.(*mqlMariadbConfSection).Name.Data)
	}
	assert.Contains(t, names, "galera")
}

// The RPM layout is the reason the flavor gate runs after include expansion.
func TestMariadbConf_RpmLayoutExpandsFragments(t *testing.T) {
	conf := mariadbConf(t, "mysql_almalinux9_mariadb.toml")
	opts := conf.GetServerOptions()
	require.NoError(t, opts.Error)

	assert.Equal(t, "/var/lib/mysql", opts.Data["datadir"])
	assert.Equal(t, "/var/log/mariadb/mariadb.log", opts.Data["log_error"])
	assert.Equal(t, "/var/lib/mysql/mysql.sock", opts.Data["socket"])

	files := conf.GetFiles()
	require.NoError(t, files.Error)
	paths := []string{}
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.Contains(t, paths, "/etc/my.cnf.d/mariadb-server.cnf")
	// enable_encryption.preset is not a .cnf and must not be read.
	for _, p := range paths {
		assert.NotContains(t, p, ".preset")
	}
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

func TestMysqlConf_Sections(t *testing.T) {
	conf := mysqlConf(t, "mysql_oracle80.toml")
	sections := conf.GetSections()
	require.NoError(t, sections.Error)

	byName := map[string]*mqlMysqlConfSection{}
	for _, s := range sections.Data {
		section := s.(*mqlMysqlConfSection)
		byName[section.Name.Data] = section
	}

	require.Contains(t, byName, "mysqld")
	mysqld := byName["mysqld"]
	assert.Equal(t, "/var/lib/mysql", mysqld.Options.Data["datadir"])
	assert.Contains(t, mysqld.Flags.Data, "skip_name_resolve")
	assert.Contains(t, mysqld.Flags.Data, "skip_host_cache")
	// A bare option reports its effective value in options.
	assert.Equal(t, "ON", mysqld.Options.Data["skip_name_resolve"])

	require.Len(t, mysqld.Files.Data, 1)
	assert.Equal(t, "/etc/my.cnf", mysqld.Files.Data[0].(*mqlFile).Path.Data)

	require.Contains(t, byName, "client")
	assert.Equal(t, "/var/run/mysqld/mysqld.sock", byName["client"].Options.Data["socket"])
}

// [mysqld_safe] and [mysqldump] are prefix neighbours of [mysqld], and the
// server reads neither as server scope.
func TestMariadbConf_MysqldSafeIsItsOwnSection(t *testing.T) {
	conf := mariadbConf(t, "mysql_debian13_mariadb.toml")
	sections := conf.GetSections()
	require.NoError(t, sections.Error)

	byName := map[string]*mqlMariadbConfSection{}
	for _, s := range sections.Data {
		section := s.(*mqlMariadbConfSection)
		byName[section.Name.Data] = section
	}

	require.Contains(t, byName, "mysqld_safe")
	safe := byName["mysqld_safe"]
	require.NotEmpty(t, safe.Options.Data, "the fixture must set something under [mysqld_safe]")

	server := conf.GetServerOptions()
	require.NoError(t, server.Error)
	for key, value := range safe.Options.Data {
		if serverValue, ok := server.Data[key]; ok {
			assert.NotEqual(t, value, serverValue,
				"option %q leaked from [mysqld_safe] into server scope", key)
		}
	}
}

// ---------------------------------------------------------------------------
// defaults for unset options
// ---------------------------------------------------------------------------

// An unset bind_address means the server listens on every interface, so an
// empty result would misreport an unrestricted listener as no listener.
func TestMysqlConf_DefaultsForUnsetOptions(t *testing.T) {
	conf := mysqlConf(t, "mysql_oracle80.toml")

	assert.Equal(t, int64(3306), conf.GetPort().Data, "port defaults to 3306")
	assert.Equal(t, []any{"*"}, conf.GetBindAddress().Data, "unset bind_address means every interface")

	// Unset booleans are false, not null, so an assertion on them fails
	// closed rather than passing on a null.
	assert.False(t, conf.GetSkipGrantTables().Data)
	assert.False(t, conf.GetRequireSecureTransport().Data)
	assert.False(t, conf.GetLocalInfile().Data)

	assert.Equal(t, int64(0), conf.GetMaxConnections().Data)
	assert.Empty(t, conf.GetSslCertFile().Data)
	assert.Empty(t, conf.GetTlsVersion().Data)
	assert.Empty(t, conf.GetCertificate().Data, "no ssl_cert means no certificates")
}

// ---------------------------------------------------------------------------
// runAsUser
// ---------------------------------------------------------------------------

func TestMysqlConf_RunAsUser(t *testing.T) {
	conf := mysqlConf(t, "mysql_user_option_files.toml")
	user := conf.GetRunAsUser()
	require.NoError(t, user.Error)
	require.NotNil(t, user.Data)
	assert.Equal(t, "mysql", user.Data.Name.Data)
	assert.Equal(t, "/bin/false", user.Data.Shell.Data)
}

// An option file may name an account that does not exist on the host. The user
// resource's own lookup fails hard in that case, and failing the whole query
// over it would be worse than reporting null.
func TestMysqlConf_RunAsUserIsNullForAnUnknownAccount(t *testing.T) {
	// The oracle80 fixture sets user=mysql but registers no /etc/passwd.
	conf := mysqlConf(t, "mysql_oracle80.toml")
	user := conf.GetRunAsUser()
	require.NoError(t, user.Error)
	assert.Nil(t, user.Data)
}

// ---------------------------------------------------------------------------
// per-user option files
// ---------------------------------------------------------------------------

func TestMysqlConf_UserFiles(t *testing.T) {
	conf := mysqlConf(t, "mysql_user_option_files.toml")
	userFiles := conf.GetUserFiles()
	require.NoError(t, userFiles.Error)

	byPath := map[string]*mqlMysqlConfUserOptionFile{}
	for _, f := range userFiles.Data {
		entry := f.(*mqlMysqlConfUserOptionFile)
		byPath[entry.File.Data.Path.Data] = entry
	}

	require.Contains(t, byPath, "/root/.my.cnf")
	root := byPath["/root/.my.cnf"]
	assert.Equal(t, "ini", root.Format.Data)
	assert.Equal(t, "root", root.Owner.Data.Name.Data)

	// The finding is that a file holding a password is readable beyond its
	// owner. Both halves are queryable rather than pre-derived.
	perms := root.File.Data.GetPermissions()
	require.NoError(t, perms.Error)
	assert.True(t, perms.Data.Other_readable.Data, "fixture is mode 0644")

	sections := root.GetSections()
	require.NoError(t, sections.Error)
	require.Len(t, sections.Data, 1)
	client := sections.Data[0].(*mqlMysqlConfSection)
	assert.Equal(t, "client", client.Name.Data)
	assert.Equal(t, "hunter2", client.Options.Data["password"])
}

// A .mylogin.cnf is an encrypted credential store. It is reported so its mode
// can be audited, but decoding it would copy the credentials it holds into
// scan results.
func TestMysqlConf_MyloginFileIsReportedButNotDecoded(t *testing.T) {
	conf := mysqlConf(t, "mysql_user_option_files.toml")
	userFiles := conf.GetUserFiles()
	require.NoError(t, userFiles.Error)

	var mylogin *mqlMysqlConfUserOptionFile
	for _, f := range userFiles.Data {
		entry := f.(*mqlMysqlConfUserOptionFile)
		if entry.Format.Data == "mylogin" {
			mylogin = entry
		}
	}
	require.NotNil(t, mylogin, "the obfuscated store must still be reported")
	assert.Equal(t, "/home/app/.mylogin.cnf", mylogin.File.Data.Path.Data)
	assert.Equal(t, "app", mylogin.Owner.Data.Name.Data)

	sections := mylogin.GetSections()
	require.NoError(t, sections.Error)
	assert.Empty(t, sections.Data, "an obfuscated store must not be decoded")
}

// ---------------------------------------------------------------------------
// parse caching
// ---------------------------------------------------------------------------

// Every derived field shares one parse. The guard behind that is a dedicated
// flag rather than a check on one of the resource's own fields, because the
// empty and error paths set state bits such a check misreads as "not yet
// done", which sends the resource into an endless re-parse.
func TestMysqlConf_ParsesOnce(t *testing.T) {
	conf := mysqlConf(t, "mysql_ubuntu2404.toml")

	require.NoError(t, conf.GetServerOptions().Error)
	firstFiles := len(conf.filesIdx)
	require.NotZero(t, firstFiles)

	// Touching more derived fields must not read another file.
	require.NoError(t, conf.GetClientOptions().Error)
	require.NoError(t, conf.GetSections().Error)
	require.NoError(t, conf.GetDatadir().Error)
	require.NoError(t, conf.GetLogError().Error)

	assert.Equal(t, firstFiles, len(conf.filesIdx), "no field may trigger a second parse")
	assert.True(t, conf.resolved)
}

// The same guard has to hold on the not-installed path, where the outcome is
// empty rather than data.
func TestMysqlConf_ParsesOnceWhenNotInstalled(t *testing.T) {
	conf := mysqlConf(t, "mysql_mariadb114.toml")

	require.NoError(t, conf.GetFile().Error)
	require.NoError(t, conf.GetServerOptions().Error)
	require.NoError(t, conf.GetSections().Error)
	require.NoError(t, conf.GetPort().Error)

	assert.True(t, conf.resolved)
	assert.Empty(t, conf.rootPath)
}

// ---------------------------------------------------------------------------
// server version detection
// ---------------------------------------------------------------------------

// binaryStrings returns the version-related strings a real server binary holds:
// the printf format string the banner is rendered from, and the version as a
// separate constant. The two never appear assembled, which is why the banner
// cannot be mined out of the file (verified against Oracle MySQL 8.0, MariaDB
// 11.8, and Percona Server 8.0, whose only "Ver " occurrences are format
// strings).
func binaryStrings(banner string) string {
	_, afterTag, _ := strings.Cut(banner, "Ver ")
	versionConstant, _, _ := strings.Cut(afterTag, " ")
	return "  Ver %s for %s on %s (%s)\n  Ver %s-debug for %s on %s (%s)\n" + versionConstant + "\n"
}

// versionRuntime builds a runtime whose only content is a server binary and the
// banner that binary prints for --version. A scan of the file must not yield a
// version, so detection has to come from running it.
func versionRuntime(t *testing.T, binary, command, banner string) *plugin.Runtime {
	t.Helper()

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "debian",
			Family: []string{"debian", "linux", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			binary: {
				Path:    binary,
				Content: binaryStrings(banner),
			},
		},
		Commands: map[string]*mock.Command{
			command: {Command: command, Stdout: banner + "\n"},
		},
	}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func mysqlResource(t *testing.T, runtime *plugin.Runtime) *mqlMysql {
	t.Helper()
	raw, err := CreateResource(runtime, "mysql", nil)
	require.NoError(t, err)
	return raw.(*mqlMysql)
}

func mariadbResource(t *testing.T, runtime *plugin.Runtime) *mqlMariadb {
	t.Helper()
	raw, err := CreateResource(runtime, "mariadb", nil)
	require.NoError(t, err)
	return raw.(*mqlMariadb)
}

func TestMysql_Version(t *testing.T) {
	for _, tc := range []struct {
		name, banner, wantVersion, wantFlavor string
	}{
		{
			"oracle mysql",
			"/usr/sbin/mysqld  Ver 8.0.46 for Linux on aarch64 (MySQL Community Server - GPL)",
			"8.0.46", "mysql",
		},
		{
			"percona server",
			"/usr/sbin/mysqld  Ver 8.0.46-37 for Linux on aarch64 (Percona Server (GPL), Release 37, Revision 39e2b60e)",
			"8.0.46", "percona",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := versionRuntime(t, "/usr/sbin/mysqld", "mysqld --version", tc.banner)

			version := mysqlResource(t, runtime).GetVersion()
			require.NoError(t, version.Error)
			assert.Equal(t, tc.wantVersion, version.Data)

			flavor := mysqlResource(t, runtime).GetFlavor()
			require.NoError(t, flavor.Error)
			assert.Equal(t, tc.wantFlavor, flavor.Data)
		})
	}
}

func TestMariadb_Version(t *testing.T) {
	runtime := versionRuntime(t, "/usr/sbin/mariadbd", "mariadbd --version",
		"mariadbd  Ver 11.8.8-MariaDB-ubu2404 for debian-linux-gnu on aarch64 (mariadb.org binary distribution)")

	version := mariadbResource(t, runtime).GetVersion()
	require.NoError(t, version.Error)
	assert.Equal(t, "11.8.8", version.Data)
}

// The version accessors are the one place the two resources can bleed into each
// other, because MariaDB installs a binary named mysqld and both products print
// the same banner shape. Each resource must report only its own product.
func TestMysqlVersion_IsNullOnMariadbHosts(t *testing.T) {
	runtime := versionRuntime(t, "/usr/sbin/mysqld", "mysqld --version",
		"mysqld  Ver 10.11.18-MariaDB-ubu2204 for debian-linux-gnu on aarch64 (mariadb.org binary distribution)")

	m := mysqlResource(t, runtime)

	version := m.GetVersion()
	require.NoError(t, version.Error)
	assert.Empty(t, version.Data, "a MariaDB banner must not be reported as a MySQL version")

	flavor := m.GetFlavor()
	require.NoError(t, flavor.Error)
	assert.Empty(t, flavor.Data)
}

func TestMariadbVersion_IsNullOnMysqlHosts(t *testing.T) {
	runtime := versionRuntime(t, "/usr/sbin/mysqld", "mysqld --version",
		"/usr/sbin/mysqld  Ver 8.0.46 for Linux on aarch64 (MySQL Community Server - GPL)")

	version := mariadbResource(t, runtime).GetVersion()
	require.NoError(t, version.Error)
	assert.Empty(t, version.Data)
}

// Version detection needs command execution. A transport that cannot run
// commands has to report nothing rather than a version guessed from the file.
func TestVersion_IsNullWithoutCommandExecution(t *testing.T) {
	asset := &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix"}},
	}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/usr/sbin/mariadbd": {
				Path:    "/usr/sbin/mariadbd",
				Content: "  Ver %s for %s on %s (%s)\n11.8.8-MariaDB-ubu2404\n",
			},
		},
	}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	mariadbVersion := mariadbResource(t, runtime).GetVersion()
	require.NoError(t, mariadbVersion.Error)
	assert.Empty(t, mariadbVersion.Data)

	mysqlVersion := mysqlResource(t, runtime).GetVersion()
	require.NoError(t, mysqlVersion.Error)
	assert.Empty(t, mysqlVersion.Data)
}

// MariaDB accepts two names for the slow query log path and treats them as one
// setting. log_slow_query_file is what its Debian and Ubuntu packages write
// into 50-server.cnf, so a reader that knows only the MySQL-compatible
// slow_query_log_file reports nothing on a packaged server whose administrator
// enabled the line the package shipped — and an operator cannot then check the
// mode of a file that holds full statement text.
func TestMariadbConf_SlowQueryLogFileReadsBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		fixture  string
		expected string
		why      string
	}{
		{
			"mysql_debian13_mariadb.toml",
			"/var/log/mysql/mariadb-slow.log",
			"log_slow_query_file is the spelling the Debian package ships",
		},
		{
			"mysql_mariadb114.toml",
			"/var/log/mysql/compat-name-slow.log",
			"slow_query_log_file is the MySQL-compatible synonym",
		},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			conf := mariadbConf(t, tc.fixture)

			enabled := conf.GetSlowQueryLog()
			require.NoError(t, enabled.Error)
			assert.True(t, enabled.Data, "the fixture enables slow query logging")

			path := conf.GetSlowQueryLogFile()
			require.NoError(t, path.Error)
			assert.Equal(t, tc.expected, path.Data, tc.why)
		})
	}
}

// A server that sets neither name reports an empty path rather than a guess.
// MariaDB derives the file from the host name under datadir in that case, which
// is not something the option file says.
func TestMariadbConf_SlowQueryLogFileIsEmptyWhenUnset(t *testing.T) {
	conf := mariadbConf(t, "mysql_almalinux9_mariadb.toml")

	path := conf.GetSlowQueryLogFile()
	require.NoError(t, path.Error)
	assert.Empty(t, path.Data)
}
