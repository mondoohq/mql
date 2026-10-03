// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// deniedDirFs refuses everything below the given directories, the way a
// non-root user sees /etc/cassandra or /etc/mysql at 0750 root:<service>:
// stat on any path inside fails with EACCES, so the scan cannot even tell
// whether a configuration file is there.
type deniedDirFs struct {
	afero.Fs
	dirs []string
}

func (f *deniedDirFs) denied(name string) error {
	for _, d := range f.dirs {
		if strings.HasPrefix(name, d+"/") {
			return &fs.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
		}
	}
	return nil
}

func (f *deniedDirFs) Stat(name string) (os.FileInfo, error) {
	if err := f.denied(name); err != nil {
		return nil, err
	}
	return f.Fs.Stat(name)
}

func (f *deniedDirFs) Open(name string) (afero.File, error) {
	if err := f.denied(name); err != nil {
		return nil, err
	}
	return f.Fs.Open(name)
}

type deniedDirConn struct {
	*mock.Connection
	fs afero.Fs
}

func (c *deniedDirConn) FileSystem() afero.Fs { return c.fs }

func (c *deniedDirConn) FileInfo(path string) (shared.FileInfoDetails, error) {
	if err := c.fs.(*deniedDirFs).denied(path); err != nil {
		return shared.FileInfoDetails{}, err
	}
	return c.Connection.FileInfo(path)
}

func newDeniedDirRuntime(t *testing.T, data *mock.TomlData, dirs ...string) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux"}},
	}, mock.WithData(data))
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: &deniedDirConn{Connection: conn, fs: &deniedDirFs{Fs: conn.FileSystem(), dirs: dirs}},
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func dirEntry(path string) *mock.MockFileData {
	return &mock.MockFileData{Path: path, StatData: mock.FileInfo{Mode: os.ModeDir | 0o750, IsDir: true}}
}

func fileEntry(path, content string) *mock.MockFileData {
	return &mock.MockFileData{Path: path, Content: content, StatData: mock.FileInfo{Mode: 0o644}}
}

// A Cassandra 5.0 node on Debian 12 with /etc/cassandra at 0750
// root:cassandra. As non-root, v13 reported no file and then the defaults:
// authenticator AllowAllAuthenticator, authenticationEnabled false and
// localJmx true, on a node running PasswordAuthenticator with remote JMX.
func cassandraDeniedRuntime(t *testing.T) *plugin.Runtime {
	return newDeniedDirRuntime(t, &mock.TomlData{Files: map[string]*mock.MockFileData{
		"/etc/cassandra":                             dirEntry("/etc/cassandra"),
		"/etc/cassandra/cassandra.yaml":              fileEntry("/etc/cassandra/cassandra.yaml", "authenticator: PasswordAuthenticator\n"),
		"/etc/cassandra/cassandra-env.sh":            fileEntry("/etc/cassandra/cassandra-env.sh", "LOCAL_JMX=no\n"),
		"/etc/cassandra/cassandra-rackdc.properties": fileEntry("/etc/cassandra/cassandra-rackdc.properties", "dc=dc1\n"),
	}}, "/etc/cassandra")
}

func TestCassandraRefusedDirReportsNullWithoutStructuredErrors(t *testing.T) {
	withStructuredErrors(t, false)
	runtime := cassandraDeniedRuntime(t)

	raw, err := CreateResource(runtime, "cassandra.conf", nil)
	require.NoError(t, err)
	conf := raw.(*mqlCassandraConf)
	file := conf.GetFile()
	require.NoError(t, file.Error)
	assert.Nil(t, file.Data, "v13 reported no file, and still does")
	for name, v := range map[string]*plugin.TValue[string]{"authenticator": conf.GetAuthenticator(), "clientEncryptionProtocol": conf.GetClientEncryptionProtocol()} {
		require.NoError(t, v.Error, name)
		assert.True(t, v.IsNull(), "%s must be null, not a default: %q", name, v.Data)
	}
	enabled := conf.GetAuthenticationEnabled()
	assert.True(t, enabled.IsNull(), "authenticationEnabled must be null, not false")

	rawEnv, err := CreateResource(runtime, "cassandra.env", nil)
	require.NoError(t, err)
	env := rawEnv.(*mqlCassandraEnv)
	require.NoError(t, env.GetLocalJmx().Error)
	assert.True(t, env.GetLocalJmx().IsNull(), "localJmx must be null, not true")

	rawRackdc, err := CreateResource(runtime, "cassandra.rackdc", nil)
	require.NoError(t, err)
	assert.True(t, rawRackdc.(*mqlCassandraRackdc).GetDc().IsNull())
}

func TestCassandraRefusedDirIsForbiddenWithStructuredErrors(t *testing.T) {
	withStructuredErrors(t, true)
	runtime := cassandraDeniedRuntime(t)

	// The resource itself is created: failing in id() would turn the
	// refusal into an unclassified RPC error.
	raw, err := CreateResource(runtime, "cassandra.conf", nil)
	require.NoError(t, err)
	conf := raw.(*mqlCassandraConf)
	assert.True(t, errors.Is(conf.GetFile().Error, llx.ErrForbidden), "file: %v", conf.GetFile().Error)
	assert.True(t, errors.Is(conf.GetAuthenticator().Error, llx.ErrForbidden))

	rawEnv, err := CreateResource(runtime, "cassandra.env", nil)
	require.NoError(t, err)
	assert.True(t, errors.Is(rawEnv.(*mqlCassandraEnv).GetLocalJmx().Error, llx.ErrForbidden))
}

// An explicit path inside a refused directory is the same refusal.
func TestCassandraRefusedExplicitPath(t *testing.T) {
	withStructuredErrors(t, false)
	runtime := cassandraDeniedRuntime(t)
	raw, err := NewResource(runtime, "cassandra.conf", map[string]*llx.RawData{"path": llx.StringData("/etc/cassandra/cassandra.yaml")})
	require.NoError(t, err)
	authenticator := raw.(*mqlCassandraConf).GetAuthenticator()
	require.NoError(t, authenticator.Error)
	assert.True(t, authenticator.IsNull())

	withStructuredErrors(t, true)
	runtime = cassandraDeniedRuntime(t)
	raw, err = NewResource(runtime, "cassandra.conf", map[string]*llx.RawData{"path": llx.StringData("/etc/cassandra/cassandra.yaml")})
	require.NoError(t, err)
	assert.True(t, errors.Is(raw.(*mqlCassandraConf).GetAuthenticator().Error, llx.ErrForbidden))
}

// Cassandra not installed at all still reads as absent, not refused.
func TestCassandraAbsentIsNotARefusal(t *testing.T) {
	withStructuredErrors(t, true)
	runtime := newDeniedDirRuntime(t, &mock.TomlData{Files: map[string]*mock.MockFileData{}})
	raw, err := CreateResource(runtime, "cassandra.conf", nil)
	require.NoError(t, err)
	file := raw.(*mqlCassandraConf).GetFile()
	require.NoError(t, file.Error)
	assert.Nil(t, file.Data)
}

// Debian 12 with Oracle MySQL 8.4 and /etc/mysql at 0750 root:mysql. As
// non-root, v13 reported no option file and then bindAddress ["*"], port
// 3306 and skipNameResolve false, while mysql.version was set.
func mysqlDeniedRuntime(t *testing.T) *plugin.Runtime {
	return newDeniedDirRuntime(t, &mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/usr/sbin/mysqld":  fileEntry("/usr/sbin/mysqld", "ELF"),
			"/etc/mysql":        dirEntry("/etc/mysql"),
			"/etc/mysql/my.cnf": fileEntry("/etc/mysql/my.cnf", "[mysqld]\nbind-address = 127.0.0.1\nskip-name-resolve\n"),
		},
		Commands: map[string]*mock.Command{
			"mysqld --version": {Command: "mysqld --version", Stdout: "/usr/sbin/mysqld  Ver 8.4.11 for Linux on x86_64 (MySQL Community Server - GPL)\n"},
		},
	}, "/etc/mysql")
}

func TestMysqlRefusedDirReportsNullWithoutStructuredErrors(t *testing.T) {
	withStructuredErrors(t, false)
	raw, err := CreateResource(mysqlDeniedRuntime(t), "mysql.conf", nil)
	require.NoError(t, err)
	conf := raw.(*mqlMysqlConf)
	file := conf.GetFile()
	require.NoError(t, file.Error)
	assert.Nil(t, file.Data)
	require.NoError(t, conf.GetBindAddress().Error)
	assert.True(t, conf.GetBindAddress().IsNull(), "bindAddress must be null, not [*]: %v", conf.GetBindAddress().Data)
	assert.True(t, conf.GetPort().IsNull(), "port must be null, not 3306")
	assert.True(t, conf.GetSkipNameResolve().IsNull(), "skipNameResolve must be null, not false")
}

func TestMysqlRefusedDirIsForbiddenWithStructuredErrors(t *testing.T) {
	withStructuredErrors(t, true)
	raw, err := CreateResource(mysqlDeniedRuntime(t), "mysql.conf", nil)
	require.NoError(t, err, "id() must not fail the resource")
	conf := raw.(*mqlMysqlConf)
	assert.True(t, errors.Is(conf.GetFile().Error, llx.ErrForbidden), "file: %v", conf.GetFile().Error)
	assert.True(t, errors.Is(conf.GetBindAddress().Error, llx.ErrForbidden))
}

// The refused /etc/mysql belongs to MySQL here, so mariadb.conf, whose
// server is not installed, still reads as absent.
func TestMysqlRefusalDoesNotSpillIntoMariadb(t *testing.T) {
	withStructuredErrors(t, true)
	raw, err := CreateResource(mysqlDeniedRuntime(t), "mariadb.conf", nil)
	require.NoError(t, err)
	file := raw.(*mqlMariadbConf).GetFile()
	require.NoError(t, file.Error)
	assert.Nil(t, file.Data)
}

// Debian 12, PostgreSQL 15, /etc/postgresql/15/main at 0750 postgres. The
// refusal was already a Forbidden error under structured errors, but it was
// raised while the resource was created, and an error there reaches the
// caller as "rpc error: code = Unknown", without its kind.
func TestPostgresqlRefusalSurvivesResourceCreation(t *testing.T) {
	withStructuredErrors(t, true)
	runtime := newDeniedDirRuntime(t, &mock.TomlData{Files: map[string]*mock.MockFileData{
		"/etc/postgresql":                         dirEntry("/etc/postgresql"),
		"/etc/postgresql/15":                      dirEntry("/etc/postgresql/15"),
		"/etc/postgresql/15/main":                 dirEntry("/etc/postgresql/15/main"),
		"/etc/postgresql/15/main/postgresql.conf": fileEntry("/etc/postgresql/15/main/postgresql.conf", "port = 5432\n"),
	}}, "/etc/postgresql/15/main")

	raw, err := CreateResource(runtime, "postgresql.conf", nil)
	require.NoError(t, err)
	file := raw.(*mqlPostgresqlConf).GetFile()
	assert.True(t, errors.Is(file.Error, llx.ErrForbidden), "file: %v", file.Error)
}
