// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The stock Debian/Ubuntu layout wraps the entire TLS VirtualHost in
// <IfModule mod_ssl.c> (sites-available/default-ssl.conf) and `Listen 443` in
// <IfModule ssl_module> (ports.conf). Before container blocks were opened up,
// both were discarded: virtualHosts came back empty and the TLS port was
// invisible, so every TLS audit passed over an empty set.
func TestParse_IfModuleWrappedVirtualHost(t *testing.T) {
	cfg := Parse(`LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so
Listen 80

<IfModule ssl_module>
	Listen 443
</IfModule>

<IfModule mod_ssl.c>
<VirtualHost _default_:443>
	ServerName secure.example.com
	SSLEngine on
	SSLProtocol -all +TLSv1.2 +TLSv1.3
	SSLCertificateFile /etc/ssl/certs/site.pem
</VirtualHost>
</IfModule>
`)

	require.Len(t, cfg.VHosts, 1)
	vh := cfg.VHosts[0]
	assert.Equal(t, "_default_:443", vh.Address)
	assert.Equal(t, "secure.example.com", vh.ServerName)
	assert.True(t, vh.SSL)
	assert.Equal(t, "-all +TLSv1.2 +TLSv1.3", vh.SSLProtocol)
	assert.Equal(t, "/etc/ssl/certs/site.pem", vh.SSLCertificateFile)

	// Both Listen directives must survive, including the conditional one.
	assert.Equal(t, "80,443", cfg.Params["Listen"])
}

func TestParse_IfDefineAndIfVersionAreTransparent(t *testing.T) {
	cfg := Parse(`Define ENABLE_ADMIN
<IfDefine ENABLE_ADMIN>
	<VirtualHost *:8080>
		ServerName admin.example.com
	</VirtualHost>
</IfDefine>

<IfVersion >= 2.4>
	ServerTokens Prod
</IfVersion>
`)

	require.Len(t, cfg.VHosts, 1)
	assert.Equal(t, "admin.example.com", cfg.VHosts[0].ServerName)
	assert.Equal(t, "Prod", cfg.Params["ServerTokens"])
}

func TestParse_NestedIfModuleBlocks(t *testing.T) {
	cfg := Parse(`LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so
Define TLS
<IfModule mod_ssl.c>
	<IfDefine TLS>
		<VirtualHost *:443>
			ServerName deep.example.com
		</VirtualHost>
	</IfDefine>
</IfModule>
`)

	require.Len(t, cfg.VHosts, 1)
	assert.Equal(t, "deep.example.com", cfg.VHosts[0].ServerName)
}

// A <Directory> block declared inside a <VirtualHost> is real configuration
// and must reach cfg.Dirs; otherwise directories.all(...) evaluates over an
// empty set on a host that does enable Indexes and .htaccess overrides.
func TestParse_DirectoryInsideVirtualHost(t *testing.T) {
	cfg := Parse(`LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
<VirtualHost *:80>
	ServerName a.example.com
	<Directory /var/www/secret>
		AllowOverride All
		Options Indexes FollowSymLinks
		Require all granted
	</Directory>
	<IfModule mod_headers.c>
		Header always set Strict-Transport-Security "max-age=63072000"
	</IfModule>
</VirtualHost>
`)

	require.Len(t, cfg.VHosts, 1)
	require.Len(t, cfg.Dirs, 1)
	d := cfg.Dirs[0]
	assert.Equal(t, "/var/www/secret", d.Path)
	assert.Equal(t, "All", d.AllowOverride)
	assert.Equal(t, "Indexes FollowSymLinks", d.Options)
	assert.Equal(t, []string{"all granted"}, d.Require)

	// A Header inside a conditional block inside the vhost still registers.
	require.Contains(t, cfg.Headers, "Strict-Transport-Security")
	assert.Equal(t, []string{"max-age=63072000"}, cfg.Headers["Strict-Transport-Security"])
}

// <RequireAll>/<RequireAny>/<RequireNone> group access-control grants. The
// grants inside them are the access-control answer, so they must be hoisted
// into the enclosing <Directory> rather than dropped — a directory whose only
// Require lives in a RequireAll must not read as having no grants at all.
func TestParse_RequireInsideRequireAll(t *testing.T) {
	cfg := Parse(`<Directory /var/www>
	<RequireAll>
		Require ip 10.0.0.0/8
		Require not ip 10.1.0.0/16
	</RequireAll>
</Directory>
`)

	require.Len(t, cfg.Dirs, 1)
	assert.Equal(t, []string{"ip 10.0.0.0/8", "not ip 10.1.0.0/16"}, cfg.Dirs[0].Require)
}

// Apache directive names are case-insensitive. Two spellings of the same
// directive must fold onto one key, so a lookup finds both values.
func TestParse_DirectiveNamesAreCaseInsensitive(t *testing.T) {
	cfg := Parse("Listen 80\nlisten 443\nSERVERTOKENS Prod\n")

	listen, ok := ParamValue(cfg.Params, "listen")
	require.True(t, ok)
	assert.Equal(t, "80,443", listen)

	tokens, ok := ParamValue(cfg.Params, "ServerTokens")
	require.True(t, ok)
	assert.Equal(t, "Prod", tokens)

	// exactly one key for Listen, not one per spelling
	count := 0
	for k := range cfg.Params {
		if k == "Listen" || k == "listen" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// A non-transparent block must still be treated as a scope: directives inside
// a <Files> block must not leak into the enclosing level's params.
func TestParse_NonTransparentBlocksStillScoped(t *testing.T) {
	cfg := Parse(`ServerName outer.example.com
<Files ".ht*">
	Require all denied
</Files>
`)

	assert.Equal(t, "outer.example.com", cfg.Params["ServerName"])
	_, leaked := cfg.Params["Require"]
	assert.False(t, leaked, "directives inside <Files> must not leak to the enclosing scope")
}

// An unterminated transparent block must not lose the directives it contains
// nor loop forever.
func TestParse_UnclosedIfModule(t *testing.T) {
	cfg := Parse("LoadModule ssl_module modules/mod_ssl.so\n<IfModule mod_ssl.c>\n\tListen 443\n")
	assert.Equal(t, "443", cfg.Params["Listen"])
}

func TestFlattenTransparentBlocks_DepthCap(t *testing.T) {
	// Build a nesting deeper than maxTransparentNesting and confirm the
	// flattener terminates rather than exhausting the stack.
	var lines []string
	for i := 0; i < maxTransparentNesting+10; i++ {
		lines = append(lines, "<IfModule mod_ssl.c>")
	}
	lines = append(lines, "Listen 443")
	for i := 0; i < maxTransparentNesting+10; i++ {
		lines = append(lines, "</IfModule>")
	}

	out := flattenTransparentBlocks(lines, nil)
	assert.NotEmpty(t, out)
}
