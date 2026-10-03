// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/resources/languages/wordpress"
	"go.mondoo.com/mql/utils/syncx"
)

func pluginTestRuntime(t *testing.T, mockFS afero.Fs) *plugin.Runtime {
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{}, "", nil, mockFS)
	require.NoError(t, err)
	return &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}
}

func writePluginTestFile(t *testing.T, mockFS afero.Fs, p string, content []byte) {
	require.NoError(t, mockFS.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, afero.WriteFile(mockFS, p, content, 0o644))
}

// the head of credentials.jpi's MANIFEST.MF, as the vendor Jenkins rpm's
// plugin and a copy of it in a second plugins directory carry it on Rocky 9
const credentialsManifest = "Manifest-Version: 1.0\r\n" +
	"Short-Name: credentials\r\n" +
	"Long-Name: Credentials Plugin\r\n" +
	"Plugin-Version: 1309.v8835d63eb_d8a_\r\n" +
	"Plugin-Dependencies: configuration-as-code:1647.ve39ca_b_829b_42;resolut\r\n" +
	" ion:=optional,structs:324.va_f5d6774f3a_d\r\n"

func jenkinsTestPlugin(t *testing.T, manifest string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("META-INF/MANIFEST.MF")
	require.NoError(t, err)
	_, err = f.Write([]byte(manifest))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func pluginFilePaths(t *testing.T, list []any) []string {
	var res []string
	for _, item := range list {
		var files []any
		switch pkg := item.(type) {
		case *mqlJenkinsPackage:
			files = pkg.Files.Data
		case *mqlWordpressPackage:
			files = pkg.Files.Data
		default:
			t.Fatalf("unexpected package type %T", item)
		}
		require.NotEmpty(t, files)
		res = append(res, files[0].(*mqlPkgFileInfo).Path.Data)
	}
	return res
}

// Two inventories of the same plugin, at the same version, in one scan: each
// reports the plugin file in its own directory.
func TestJenkinsPackagesOfTwoDirectoriesKeepTheirFiles(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	jpi := jenkinsTestPlugin(t, credentialsManifest)
	writePluginTestFile(t, mockFS, "/var/lib/jenkins/plugins/credentials.jpi", jpi)
	writePluginTestFile(t, mockFS, "/srv/g09/fx/jenkins/plugins/credentials.jpi", jpi)
	runtime := pluginTestRuntime(t, mockFS)

	list := func(p string) []any {
		res, err := CreateResource(runtime, "jenkins.packages", map[string]*llx.RawData{"path": llx.StringData(p)})
		require.NoError(t, err)
		pkgs := res.(*mqlJenkinsPackages)
		require.NoError(t, pkgs.gatherData())
		return pkgs.List.Data
	}
	assert.Equal(t, []string{"/var/lib/jenkins/plugins/credentials.jpi"}, pluginFilePaths(t, list("/var/lib/jenkins/plugins")))
	assert.Equal(t, []string{"/srv/g09/fx/jenkins/plugins/credentials.jpi"}, pluginFilePaths(t, list("/srv/g09/fx/jenkins/plugins")))
}

const akismetMain = `<?php
/**
 * @package Akismet
 */
/*
Plugin Name: Akismet Anti-spam: Spam Protection
Plugin URI: https://akismet.com/
Version: 5.3.3
Requires at least: 5.8
Requires PHP: 5.6.20
Author: Automattic - Anti-spam Team
License: GPLv2 or later
Text Domain: akismet
*/
`

func TestWordpressPackagesOfTwoSitesKeepTheirFiles(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	writePluginTestFile(t, mockFS, "/srv/www/htdocs/wordpress/wp-content/plugins/akismet/akismet.php", []byte(akismetMain))
	writePluginTestFile(t, mockFS, "/var/www/wordpress/wp-content/plugins/akismet/akismet.php", []byte(akismetMain))
	runtime := pluginTestRuntime(t, mockFS)

	list := func(p string) []any {
		res, err := CreateResource(runtime, "wordpress.packages", map[string]*llx.RawData{"path": llx.StringData(p)})
		require.NoError(t, err)
		pkgs := res.(*mqlWordpressPackages)
		require.NoError(t, pkgs.gatherData())
		return pkgs.List.Data
	}
	assert.Equal(t, []string{"/var/www/wordpress/wp-content/plugins/akismet/akismet.php"},
		pluginFilePaths(t, list("/var/www/wordpress/wp-content/plugins")))
	assert.Equal(t, []string{"/srv/www/htdocs/wordpress/wp-content/plugins/akismet/akismet.php"},
		pluginFilePaths(t, list("/srv/www/htdocs/wordpress/wp-content/plugins")))

	// the default scan lists both sites
	assert.ElementsMatch(t, []string{
		"/srv/www/htdocs/wordpress/wp-content/plugins/akismet/akismet.php",
		"/var/www/wordpress/wp-content/plugins/akismet/akismet.php",
	}, pluginFilePaths(t, list("")))
}

func TestDedupeWordPressPlugins(t *testing.T) {
	plugin := func(dir string) wordpress.WordPressPlugin {
		return wordpress.WordPressPlugin{Slug: "akismet", Version: "5.3.3", FilePath: dir + "/akismet/akismet.php"}
	}
	t.Run("Debian links the bundled plugins into /var/lib/wordpress", func(t *testing.T) {
		in := []wordpress.WordPressPlugin{
			plugin("/usr/share/wordpress/wp-content/plugins"),
			plugin("/var/lib/wordpress/wp-content/plugins"),
		}
		real := map[string]string{
			"/usr/share/wordpress/wp-content/plugins/akismet/akismet.php": "/usr/share/wordpress/wp-content/plugins/akismet/akismet.php",
			"/var/lib/wordpress/wp-content/plugins/akismet/akismet.php":   "/usr/share/wordpress/wp-content/plugins/akismet/akismet.php",
		}
		assert.Equal(t, in[:1], dedupeWordPressPlugins(in, real))
	})
	t.Run("two sites with the same plugin version", func(t *testing.T) {
		in := []wordpress.WordPressPlugin{
			plugin("/srv/www/htdocs/wordpress/wp-content/plugins"),
			plugin("/var/www/wordpress/wp-content/plugins"),
		}
		assert.Equal(t, in, dedupeWordPressPlugins(in, map[string]string{}))
	})
}
