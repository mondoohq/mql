// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func missingPathRuntime(t *testing.T, platform *inventory.Platform, files map[string]*mock.MockFileData, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	for p, f := range files {
		f.Path = p
	}
	if commands == nil {
		commands = map[string]*mock.Command{}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(&mock.TomlData{Files: files, Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

var rhel9Platform = &inventory.Platform{Name: "rhel", Version: "9.6", Family: []string{"redhat", "linux", "unix", "os"}}

// A path named explicitly must exist, as with snmpd.config, nginx.conf and
// haproxy.config: reading it as an empty configuration let
// localInterfaces.all(_ == "127.0.0.1") and acls.none(...) pass on a file
// that is not there. A missing default location still means not installed.
func TestExplicitMissingConfigPaths(t *testing.T) {
	t.Run("squid.conf", func(t *testing.T) {
		rt := missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, nil)
		res, err := NewResource(rt, "squid.conf", map[string]*llx.RawData{"path": llx.StringData("/nonexistent/squid.conf")})
		require.NoError(t, err)
		conf := res.(*mqlSquidConf)
		assert.ErrorContains(t, conf.GetAcls().Error, "/nonexistent/squid.conf")

		rt = missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, nil)
		res, err = NewResource(rt, "squid.conf", nil)
		require.NoError(t, err)
		acls := res.(*mqlSquidConf).GetAcls()
		require.NoError(t, acls.Error)
		assert.Empty(t, acls.Data)
	})

	t.Run("exim", func(t *testing.T) {
		rt := missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, nil)
		res, err := NewResource(rt, "exim", map[string]*llx.RawData{"path": llx.StringData("/nonexistent/exim.conf")})
		require.NoError(t, err)
		e := res.(*mqlExim)
		assert.ErrorContains(t, e.GetParams().Error, "/nonexistent/exim.conf")
		assert.Error(t, e.GetLocalInterfaces().Error)
	})

	t.Run("postfix", func(t *testing.T) {
		rt := missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, map[string]*mock.Command{
			"postconf -c /nonexistent": {ExitStatus: 1, Stderr: "postconf: fatal: open /nonexistent/main.cf: No such file or directory"},
		})
		res, err := NewResource(rt, "postfix", map[string]*llx.RawData{"path": llx.StringData("/nonexistent/main.cf")})
		require.NoError(t, err)
		p := res.(*mqlPostfix)
		assert.ErrorContains(t, p.GetInetInterfaces().Error, "/nonexistent/main.cf")
		assert.Error(t, p.GetServices().Error)

		rt = missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, map[string]*mock.Command{
			"postconf -c /etc/postfix": {ExitStatus: 127},
		})
		res, err = NewResource(rt, "postfix", nil)
		require.NoError(t, err)
		params := res.(*mqlPostfix).GetParams()
		require.NoError(t, params.Error)
		assert.Empty(t, params.Data)
	})

	t.Run("tomcat home", func(t *testing.T) {
		rt := tomcatMockRuntime(t, map[string]*mock.MockFileData{})
		raw, err := CreateResource(rt, "tomcat", map[string]*llx.RawData{"home": llx.StringData("/nonexistent")})
		require.NoError(t, err)
		tc := raw.(*mqlTomcat)
		assert.ErrorContains(t, tc.GetUsers().Error, "/nonexistent")
		assert.Error(t, tc.GetServer().Error)
		assert.Error(t, tc.GetProperties().Error)
	})

	t.Run("tomcat home that exists", func(t *testing.T) {
		tc := tomcatMockInstallation(t, nil)
		users := tc.GetUsers()
		require.NoError(t, users.Error)
		assert.Empty(t, users.Data)
	})
}

// The install directory's name is only a version when the directory is there.
func TestJbossVersionNeedsAnInstallDir(t *testing.T) {
	rt := jbossMockRuntime(t, map[string]*mock.MockFileData{})
	raw, err := CreateResource(rt, "jboss", map[string]*llx.RawData{"home": llx.StringData("/opt/wildfly-99.0.0.Final")})
	require.NoError(t, err)
	v := raw.(*mqlJboss).GetVersion()
	require.NoError(t, v.Error)
	assert.True(t, v.IsNull(), "got %q", v.Data)

	rt = jbossMockRuntime(t, map[string]*mock.MockFileData{
		"/opt/wildfly-26.1.3.Final":                   jbossDir(),
		"/opt/wildfly-26.1.3.Final/jboss-modules.jar": jbossFile("jar"),
	})
	raw, err = CreateResource(rt, "jboss", map[string]*llx.RawData{"home": llx.StringData("/opt/wildfly-26.1.3.Final")})
	require.NoError(t, err)
	assert.Equal(t, "26.1.3.Final", raw.(*mqlJboss).GetVersion().Data)
}
