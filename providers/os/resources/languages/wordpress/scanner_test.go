// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wordpress

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanPluginDir(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	plugins, err := ScanPluginDir(afs, "./testdata")
	require.NoError(t, err)

	// not-a-plugin is skipped (no readme.txt, no main plugin file)
	assert.Equal(t, 6, len(plugins))

	var akismet, cf7 *WordPressPlugin
	for i := range plugins {
		switch plugins[i].Slug {
		case "akismet":
			akismet = &plugins[i]
		case "contact-form-7":
			cf7 = &plugins[i]
		}
	}

	require.NotNil(t, akismet)
	assert.Equal(t, "akismet", akismet.Slug)
	assert.Equal(t, "5.3.3", akismet.Version)
	assert.Equal(t, "Akismet Anti-spam: Spam Protection", akismet.DisplayName)
	assert.Equal(t, "GPLv2 or later", akismet.License)
	assert.Equal(t, "5.8", akismet.RequiresWp)
	assert.Equal(t, "6.6", akismet.TestedUpTo)

	require.NotNil(t, cf7)
	assert.Equal(t, "contact-form-7", cf7.Slug)
	assert.Equal(t, "5.9.8", cf7.Version)
	assert.Equal(t, "Contact Form 7", cf7.DisplayName)
	assert.Equal(t, "6.2", cf7.RequiresWp)
}

func TestExtractPluginName(t *testing.T) {
	assert.Equal(t, "Akismet Anti-spam: Spam Protection", extractPluginName("=== Akismet Anti-spam: Spam Protection ==="))
	assert.Equal(t, "Hello", extractPluginName("=== Hello ==="))
	assert.Equal(t, "", extractPluginName("Not a plugin name"))
	assert.Equal(t, "", extractPluginName(""))
}

func TestNewPackageUrl(t *testing.T) {
	assert.Equal(t, "pkg:wordpress-plugin/akismet@5.3.3", NewPackageUrl("akismet", "5.3.3"))
}

func pluginsBySlug(t *testing.T, plugins []WordPressPlugin) map[string]WordPressPlugin {
	t.Helper()
	out := map[string]WordPressPlugin{}
	for _, p := range plugins {
		out[p.Slug] = p
	}
	return out
}

// The version WordPress reports for an installed plugin is the "Version"
// header of its main file. readme.txt's "Stable tag" names the latest release
// in the plugin directory, which an older or newer copy on disk need not match:
// the WooCommerce fixture is 8.0.0 with a readme still saying 7.9.0.
func TestScanPluginDirVersionFromMainPluginFile(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	plugins, err := ScanPluginDir(afs, "./testdata")
	require.NoError(t, err)
	bySlug := pluginsBySlug(t, plugins)

	woo := bySlug["woocommerce"]
	assert.Equal(t, "8.0.0", woo.Version)
	assert.Equal(t, "WooCommerce", woo.DisplayName)
	assert.Equal(t, "6.2", woo.RequiresWp)
	assert.Equal(t, "6.3", woo.TestedUpTo, "only readme.txt carries Tested up to")
	assert.Equal(t, "GPLv3", woo.License, "the main file has no License header, the readme does")
	assert.Equal(t, "testdata/woocommerce/woocommerce.php", woo.FilePath)
	assert.Equal(t, "testdata/woocommerce/readme.txt", woo.ReadmePath)

	// the main file is hello.php, not <slug>.php, and its docblock's
	// "@version 1.7.2" has no colon, so it is not a header
	hello := bySlug["hello-dolly"]
	assert.Equal(t, "1.7.2", hello.Version)
	assert.Equal(t, "testdata/hello-dolly/hello.php", hello.FilePath)
	assert.Equal(t, "4.6", hello.RequiresWp)

	// a plugin with no readme.txt is still installed
	noReadme := bySlug["no-readme"]
	assert.Equal(t, "2.1.0", noReadme.Version)
	assert.Equal(t, "Example Site Tweaks", noReadme.DisplayName)
	assert.Equal(t, "GPL-2.0-or-later", noReadme.License)
	assert.Equal(t, "", noReadme.ReadmePath)

	// no main plugin file: the readme is all there is
	readmeOnly := bySlug["readme-only-plugin"]
	assert.Equal(t, "1.0.4", readmeOnly.Version)
	assert.Equal(t, "testdata/readme-only-plugin/readme.txt", readmeOnly.FilePath)

	_, ok := bySlug["not-a-plugin"]
	assert.False(t, ok)
}

func TestParsePluginHeaders(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "plain comment block, as akismet writes it",
			in:   "<?php\n/*\nPlugin Name: Akismet Anti-Spam: Spam Protection\nVersion: 5.1\nRequires at least: 5.0\nLicense: GPLv2 or later\n*/\n",
			want: map[string]string{"plugin name": "Akismet Anti-Spam: Spam Protection", "version": "5.1", "requires at least": "5.0", "license": "GPLv2 or later"},
		},
		{
			name: "docblock with aligned values",
			in:   "<?php\n/**\n * Plugin Name: Yoast Duplicate Post\n * Version:     4.7\n */\n",
			want: map[string]string{"plugin name": "Yoast Duplicate Post", "version": "4.7"},
		},
		{
			name: "header and comment end on one line",
			in:   "<?php /* Plugin Name: One Liner */\n// Version: 0.3 ?>\n",
			want: map[string]string{"plugin name": "One Liner", "version": "0.3"},
		},
		{
			name: "case-insensitive, first match wins, CRLF",
			in:   "<?php\r\n/*\r\nPLUGIN NAME: Shouty\r\nversion: 1.0\r\nVersion: 2.0\r\n*/\r\n",
			want: map[string]string{"plugin name": "Shouty", "version": "1.0"},
		},
		{
			name: "a docblock tag without a colon is not a header",
			in:   "<?php\n/**\n * @version 1.7.2\n */\n",
			want: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parsePluginHeaders([]byte(tt.in)))
		})
	}
}

// Debian's wordpress package links the bundled plugins into
// /var/lib/wordpress/wp-content/plugins. A symlinked plugin directory is a
// plugin like any other.
func TestScanPluginDirFollowsSymlinkedPluginDirectories(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "usr-share-wordpress-plugins")
	site := filepath.Join(root, "var-lib-wordpress-plugins")
	require.NoError(t, os.MkdirAll(filepath.Join(shared, "akismet"), 0o755))
	require.NoError(t, os.MkdirAll(site, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(shared, "akismet", "akismet.php"),
		[]byte("<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.3\n*/\n"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(shared, "akismet"), filepath.Join(site, "akismet")))
	// a symlink to a file is not a plugin
	require.NoError(t, os.WriteFile(filepath.Join(shared, "index.php"), []byte("<?php\n"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(shared, "index.php"), filepath.Join(site, "index.php")))

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	plugins, err := ScanPluginDir(afs, site)
	require.NoError(t, err)
	require.Len(t, plugins, 1)
	assert.Equal(t, "akismet", plugins[0].Slug)
	assert.Equal(t, "5.3.3", plugins[0].Version)
}

// WordPress also loads a PHP file directly in the plugins directory as a
// plugin when it carries a "Plugin Name" header. The wordpress rpm on Fedora
// and EPEL ships Hello Dolly that way (hello.php, copied from the package),
// next to an index.php with no header that is not a plugin.
func TestScanPluginDirSingleFilePlugins(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	plugins, err := ScanPluginDir(afs, "./testdata/single-file/wp-content/plugins")
	require.NoError(t, err)
	bySlug := pluginsBySlug(t, plugins)
	require.Len(t, bySlug, 3)

	// the slug is the Text Domain, which wordpress.org requires to match the
	// plugin's slug, not the file name
	hello, ok := bySlug["hello-dolly"]
	require.True(t, ok)
	assert.Equal(t, "1.7.2", hello.Version)
	assert.Equal(t, "Hello Dolly", hello.DisplayName)
	assert.Equal(t, "testdata/single-file/wp-content/plugins/hello.php", hello.FilePath)
	assert.Equal(t, "", hello.ReadmePath)

	// without a Text Domain the file name is the slug
	tweaks, ok := bySlug["site-tweaks"]
	require.True(t, ok)
	assert.Equal(t, "0.2.0", tweaks.Version)

	assert.Equal(t, "5.5", bySlug["akismet"].Version)
	_, ok = bySlug["index"]
	assert.False(t, ok, "index.php has no plugin header")
}
