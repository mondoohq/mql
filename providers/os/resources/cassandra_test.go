// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestCassandraVersionCommands(t *testing.T) {
	// The Debian and RPM packages install the launch script as
	// /usr/sbin/cassandra (Debian 9 to 13 with Cassandra 3.11.19 to 5.0.9,
	// RHEL 9 with 5.0.9), which is not on a non-root user's PATH
	// (/usr/local/bin:/usr/bin:/bin:/usr/games on Debian), so it is probed
	// by absolute path. The tarball layout keeps the launch script next to the conf
	// directory: /opt/cassandra/conf and /opt/cassandra/bin/cassandra
	// (Apache Cassandra 4.1.12 unpacked under /opt on RHEL 7, which puts
	// nothing on PATH). Package layouts install `cassandra` on PATH, so
	// /etc/cassandra yields no sibling binary.
	assert.Equal(t, []string{
		"/usr/sbin/cassandra",
		"/usr/bin/cassandra",
		"/opt/cassandra/bin/cassandra",
		"/usr/local/cassandra/bin/cassandra",
	}, cassandraBinaries([]string{
		"/etc/cassandra",
		"/etc/cassandra/conf",
		"/opt/cassandra/conf",
		"/usr/local/cassandra/conf",
		"/opt/homebrew/etc/cassandra",
	}))
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

// RHEL 7 with Cassandra 4.1.10 unpacked under its versioned name and no
// /opt/cassandra symlink.
func TestCassandraFindsVersionedTarball(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for _, p := range []string{"/opt/apache-cassandra-4.1.10/conf/cassandra.yaml", "/opt/apache-cassandra-4.0.1/conf/cassandra.yaml"} {
		require.NoError(t, afs.WriteFile(p, []byte("x"), 0o644))
	}
	paths := cassandraConfPaths(afs, "cassandra.yaml")
	assert.Equal(t, "/opt/apache-cassandra-4.1.10/conf/cassandra.yaml", paths[len(paths)-2])
	assert.Equal(t, "/opt/apache-cassandra-4.0.1/conf/cassandra.yaml", paths[len(paths)-1])
	assert.Contains(t, cassandraBinaries(cassandraConfDirsOn(afs)), "/opt/apache-cassandra-4.1.10/bin/cassandra")
}
