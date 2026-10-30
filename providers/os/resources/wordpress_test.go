// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/languages/wordpress"
)

// akismetReadme is the start of the readme.txt of the akismet plugin bundled
// with WordPress 6.6.2, as installed on a SLES 15 SP7 host.
const akismetReadme = `=== Akismet Anti-spam: Spam Protection ===
Contributors: matt, ryan, andy, mdawaffe, tellyworth, josephscott, lessbloat, eoigal, cfinke, automattic, jgs, procifer, stephdau, kbrownkd, bluefuton, akismetantispam
Stable tag: 5.3.3
`

// SUSE's Apache serves /srv/www/htdocs. Fails if the SUSE document root paths
// are dropped from defaultWordPressPluginPaths: WordPress installed there was
// invisible to the default scan, and a plugin version check passed.
func TestWordPressDefaultsSUSEDocroot(t *testing.T) {
	for _, dir := range []string{"/srv/www/htdocs/wordpress", "/srv/www/htdocs"} {
		t.Run(dir, func(t *testing.T) {
			mockFS := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mockFS, dir+"/wp-content/plugins/akismet/readme.txt", []byte(akismetReadme), 0o644))

			r := &mqlWordpressPackages{MqlRuntime: memFSRuntime(t, mockFS)}
			require.NoError(t, r.gatherData())
			require.Len(t, r.List.Data, 1)
			pkg := r.List.Data[0].(*mqlWordpressPackage)
			assert.Equal(t, "akismet", pkg.Name.Data)
			assert.Equal(t, "5.3.3", pkg.Version.Data)
		})
	}
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
	writeMemFSFile(t, mockFS, "/srv/www/htdocs/wordpress/wp-content/plugins/akismet/akismet.php", []byte(akismetMain))
	writeMemFSFile(t, mockFS, "/var/www/wordpress/wp-content/plugins/akismet/akismet.php", []byte(akismetMain))
	runtime := memFSRuntime(t, mockFS)

	list := func(p string) []any {
		res, err := CreateResource(runtime, "wordpress.packages", map[string]*llx.RawData{"path": llx.StringData(p)})
		require.NoError(t, err)
		pkgs := res.(*mqlWordpressPackages)
		require.NoError(t, pkgs.gatherData())
		return pkgs.List.Data
	}
	assert.Equal(t, []string{"/var/www/wordpress/wp-content/plugins/akismet/akismet.php"},
		wordpressFilePaths(t, list("/var/www/wordpress/wp-content/plugins")))
	assert.Equal(t, []string{"/srv/www/htdocs/wordpress/wp-content/plugins/akismet/akismet.php"},
		wordpressFilePaths(t, list("/srv/www/htdocs/wordpress/wp-content/plugins")))

	// the default scan lists both sites
	assert.ElementsMatch(t, []string{
		"/srv/www/htdocs/wordpress/wp-content/plugins/akismet/akismet.php",
		"/var/www/wordpress/wp-content/plugins/akismet/akismet.php",
	}, wordpressFilePaths(t, list("")))
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

func wordpressFilePaths(t *testing.T, list []any) []string {
	var res []string
	for _, item := range list {
		files := item.(*mqlWordpressPackage).Files.Data
		require.NotEmpty(t, files)
		res = append(res, files[0].(*mqlPkgFileInfo).Path.Data)
	}
	return res
}
