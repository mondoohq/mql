// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

const tomcatTestHome = "/usr/local/tomcat"

func tomcatMockRuntime(t *testing.T, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()

	for path, file := range files {
		file.Path = path
	}

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "linux",
			Family:  []string{"linux", "unix", "os"},
			Version: "test",
		},
	}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{},
		Files:    files,
	}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// tomcatMockInstallation returns a minimal installation with the given extra
// files layered on top. home and base are passed to the resource directly, so
// the test exercises parsing rather than discovery.
func tomcatMockInstallation(t *testing.T, extra map[string]*mock.MockFileData) *mqlTomcat {
	t.Helper()

	files := map[string]*mock.MockFileData{
		tomcatTestHome:                       {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		tomcatTestHome + "/conf":             {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		tomcatTestHome + "/lib":              {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		tomcatTestHome + "/lib/catalina.jar": {StatData: mock.FileInfo{Mode: 0o644}, Content: "jar"},
	}
	for path, file := range extra {
		files[path] = file
	}

	runtime := tomcatMockRuntime(t, files)
	raw, err := CreateResource(runtime, "tomcat", map[string]*llx.RawData{
		"home": llx.StringData(tomcatTestHome),
		"base": llx.StringData(tomcatTestHome),
	})
	require.NoError(t, err)
	return raw.(*mqlTomcat)
}

func tomcatFile(content string) *mock.MockFileData {
	return &mock.MockFileData{
		StatData: mock.FileInfo{Mode: 0o644},
		Content:  content,
	}
}

// requireResolvedNull asserts the runtime contract for "there is nothing here":
// the field is marked resolved and null. A field that is merely left nil is
// never marked resolved, so the runtime keeps asking for it.
func requireResolvedNull(t *testing.T, state plugin.State, err error, data any, field string) {
	t.Helper()
	require.NoError(t, err, field)
	assert.Nil(t, data, "%s must be null", field)
	assert.NotZero(t, state&plugin.StateIsSet, "%s must be marked as resolved", field)
	assert.NotZero(t, state&plugin.StateIsNull, "%s must be marked as null", field)
}

// TestTomcatUnparsableFilesResolveToNull is the regression for a configuration
// file that exists but yields nothing: it is empty, or it holds only a comment,
// or its root element is not the one the field parses. The field has to resolve
// to null. Returning a bare nil leaves it unresolved, which the runtime treats
// as a provider that never answered.
func TestTomcatUnparsableFilesResolveToNull(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"empty file", ""},
		{"whitespace only", "\n   \n\t\n"},
		{"comment without a root element", "<?xml version=\"1.0\"?>\n<!-- everything here is commented out -->\n"},
		{"wrong root element", "<Server port=\"8005\" shutdown=\"SHUTDOWN\"/>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("web.xml", func(t *testing.T) {
				installation := tomcatMockInstallation(t, map[string]*mock.MockFileData{
					tomcatTestHome + "/conf/web.xml": tomcatFile(tc.content),
				})

				webXml := installation.GetWebXml()
				requireResolvedNull(t, webXml.State, webXml.Error, webXml.Data, "tomcat.webXml")
			})

			t.Run("context.xml", func(t *testing.T) {
				content := tc.content
				if tc.name == "wrong root element" {
					content = "<web-app version=\"6.0\"/>"
				}
				installation := tomcatMockInstallation(t, map[string]*mock.MockFileData{
					tomcatTestHome + "/conf/context.xml": tomcatFile(content),
				})

				ctx := installation.GetContext()
				requireResolvedNull(t, ctx.State, ctx.Error, ctx.Data, "tomcat.context")
			})

			t.Run("server.xml", func(t *testing.T) {
				content := tc.content
				if tc.name == "wrong root element" {
					content = "<Context path=\"/app\"/>"
				}
				installation := tomcatMockInstallation(t, map[string]*mock.MockFileData{
					tomcatTestHome + "/conf/server.xml": tomcatFile(content),
				})

				server := installation.GetServer()
				requireResolvedNull(t, server.State, server.Error, server.Data, "tomcat.server")
			})
		})
	}
}

// TestTomcatMissingFilesResolveToNull covers the same contract for a file that
// is not on disk at all.
func TestTomcatMissingFilesResolveToNull(t *testing.T) {
	installation := tomcatMockInstallation(t, nil)

	server := installation.GetServer()
	requireResolvedNull(t, server.State, server.Error, server.Data, "tomcat.server")

	webXml := installation.GetWebXml()
	requireResolvedNull(t, webXml.State, webXml.Error, webXml.Data, "tomcat.webXml")

	ctx := installation.GetContext()
	requireResolvedNull(t, ctx.State, ctx.Error, ctx.Data, "tomcat.context")

	// Map-valued fields have no null state to get wrong; they resolve empty.
	properties := installation.GetProperties()
	require.NoError(t, properties.Error)
	assert.Empty(t, properties.Data)

	users := installation.GetUsers()
	require.NoError(t, users.Error)
	assert.Empty(t, users.Data)
}

// TestTomcatWebappUnparsableFilesResolveToNull is the same regression one level
// down, where an application ships a descriptor that holds nothing.
func TestTomcatWebappUnparsableFilesResolveToNull(t *testing.T) {
	appDir := tomcatTestHome + "/webapps/myapp"
	installation := tomcatMockInstallation(t, map[string]*mock.MockFileData{
		tomcatTestHome + "/conf/server.xml": tomcatFile(`<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps"/>
    </Engine>
  </Service>
</Server>`),
		tomcatTestHome + "/webapps":      {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		appDir:                           {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		appDir + "/META-INF":             {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		appDir + "/META-INF/context.xml": tomcatFile(""),
		appDir + "/WEB-INF":              {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		appDir + "/WEB-INF/web.xml":      tomcatFile("<!-- deliberately empty -->"),
	})

	webapps := installation.GetWebapps()
	require.NoError(t, webapps.Error)
	require.Len(t, webapps.Data, 1)

	app := webapps.Data[0].(*mqlTomcatWebapp)
	assert.Equal(t, "myapp", app.GetName().Data)

	ctx := app.GetContext()
	requireResolvedNull(t, ctx.State, ctx.Error, ctx.Data, "tomcat.webapp.context")

	webXml := app.GetWebXml()
	requireResolvedNull(t, webXml.State, webXml.Error, webXml.Data, "tomcat.webapp.webXml")

	logging := app.GetLogging()
	require.NoError(t, logging.Error)
	assert.Empty(t, logging.Data)
}

// TestTomcatNotInstalledResolvesCleanly covers an asset with no Tomcat at all:
// discovery finds nothing and every field still answers.
func TestTomcatNotInstalledResolvesCleanly(t *testing.T) {
	runtime := tomcatMockRuntime(t, map[string]*mock.MockFileData{
		"/etc/passwd": tomcatFile("root:x:0:0::/root:/bin/sh\n"),
	})
	raw, err := CreateResource(runtime, "tomcat", map[string]*llx.RawData{})
	require.NoError(t, err)
	installation := raw.(*mqlTomcat)

	assert.Empty(t, installation.GetHome().Data)
	assert.Empty(t, installation.GetBase().Data)

	server := installation.GetServer()
	requireResolvedNull(t, server.State, server.Error, server.Data, "tomcat.server")

	webapps := installation.GetWebapps()
	require.NoError(t, webapps.Error)
	assert.Empty(t, webapps.Data)
}

// SUSE's tomcat-webapps and tomcat-admin-webapps packages deploy ROOT,
// manager, host-manager and examples into /srv/tomcat/webapps as symlinks into
// /usr/share/tomcat/tomcat-webapps. ReadDir on the local filesystem returns the
// links' own (lstat) modes, so the links must be followed to see they are
// applications.
func TestIsWebappDirFollowsSymlinks(t *testing.T) {
	root := t.TempDir()
	share := filepath.Join(root, "share")
	appBase := filepath.Join(root, "webapps")
	require.NoError(t, os.MkdirAll(filepath.Join(share, "manager"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(appBase, "local"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(share, "notes.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(appBase, "app.war"), []byte("PK"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(share, "manager"), filepath.Join(appBase, "manager")))
	require.NoError(t, os.Symlink(filepath.Join(share, "notes.txt"), filepath.Join(appBase, "notes")))
	require.NoError(t, os.Symlink(filepath.Join(share, "gone"), filepath.Join(appBase, "dangling")))

	fs := afero.NewOsFs()
	entries, err := afero.ReadDir(fs, appBase)
	require.NoError(t, err)

	got := map[string]bool{}
	for _, entry := range entries {
		got[entry.Name()] = isWebappDir(fs, filepath.Join(appBase, entry.Name()), entry)
	}
	assert.Equal(t, map[string]bool{
		"local":    true,
		"manager":  true,
		"app.war":  false,
		"notes":    false,
		"dangling": false,
	}, got)
}

// A path named explicitly must exist, as with snmpd.config, nginx.conf and
// haproxy.config: reading it as an empty configuration let
// localInterfaces.all(_ == "127.0.0.1") and acls.none(...) pass on a file
// that is not there. A missing default location still means not installed.
func TestTomcatExplicitMissingConfigPaths(t *testing.T) {
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
