// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// debianStatic is what `apache2 -l` prints on Ubuntu 16.04 through 24.04.
var debianStatic = []string{
	"core.c", "mod_so.c", "mod_watchdog.c", "http_core.c",
	"mod_log_config.c", "mod_logio.c", "mod_version.c", "mod_unixd.c",
}

// ubuntuTree is a trimmed copy of the stock Ubuntu 24.04 layout: the
// apache2.conf include order, the real ports.conf and serve-cgi-bin.conf, and
// the module set the sweep hosts have enabled (ssl, headers, alias; no
// mod_cgi, mod_cgid or mod_gnutls).
func ubuntuTree(extra map[string]string) map[string]string {
	files := map[string]string{
		"/etc/apache2/apache2.conf": `ServerRoot "/etc/apache2"
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
Include ports.conf
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
`,
		"/etc/apache2/mods-enabled/alias.load":   "LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so\n",
		"/etc/apache2/mods-enabled/headers.load": "LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so\n",
		"/etc/apache2/mods-enabled/ssl.load":     "# Depends: mime socache_shmcb\nLoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so\n",
		"/etc/apache2/mods-enabled/autoindex.conf": `<IfModule mod_autoindex.c>
	IndexOptions FancyIndexing
</IfModule>
`,
		"/etc/apache2/ports.conf": `Listen 80

<IfModule ssl_module>
	Listen 443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 443
</IfModule>
`,
		"/etc/apache2/conf-enabled/serve-cgi-bin.conf": `<IfModule mod_alias.c>
	<IfModule mod_cgi.c>
		Define ENABLE_USR_LIB_CGI_BIN
	</IfModule>

	<IfModule mod_cgid.c>
		Define ENABLE_USR_LIB_CGI_BIN
	</IfModule>

	<IfDefine ENABLE_USR_LIB_CGI_BIN>
		ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
		<Directory "/usr/lib/cgi-bin">
			AllowOverride None
			Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
			Require all granted
		</Directory>
	</IfDefine>
</IfModule>
`,
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func parseTree(t *testing.T, files map[string]string, opts ParseOptions) *Config {
	t.Helper()
	fileContent := func(p string) (string, error) {
		c, ok := files[p]
		if !ok {
			return "", fmt.Errorf("not found: %s", p)
		}
		return c, nil
	}
	globExpand := func(pattern string) ([]string, error) {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join("/etc/apache2", pattern)
		}
		var out []string
		for p := range files {
			if ok, _ := filepath.Match(pattern, p); ok {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	cfg, err := ParseWithGlobOptions("/etc/apache2/apache2.conf", fileContent, globExpand, nil, opts)
	require.NoError(t, err)
	return cfg
}

// ports.conf lists `Listen 443` twice, once for mod_ssl and once for
// mod_gnutls. Only mod_ssl is loaded, so `apache2ctl -t -D DUMP_CONFIG` on the
// sweep hosts shows Listen 80 and a single Listen 443.
func TestConditional_PortsConfOnlyLoadedModuleBranch(t *testing.T) {
	cfg := parseTree(t, ubuntuTree(nil), ParseOptions{StaticModules: debianStatic})
	assert.Equal(t, "80,443", cfg.Params["Listen"])
}

// With mod_ssl disabled (a2dismod ssl), neither branch applies and Apache only
// listens on 80.
func TestConditional_PortsConfWithoutSSL(t *testing.T) {
	files := ubuntuTree(nil)
	delete(files, "/etc/apache2/mods-enabled/ssl.load")
	cfg := parseTree(t, files, ParseOptions{StaticModules: debianStatic})
	assert.Equal(t, "80", cfg.Params["Listen"])
}

// serve-cgi-bin.conf only defines ENABLE_USR_LIB_CGI_BIN when mod_cgi or
// mod_cgid is loaded. Neither is, so the /usr/lib/cgi-bin directory and its
// ScriptAlias do not exist in the running config.
func TestConditional_ServeCgiBinNeedsCgiModule(t *testing.T) {
	cfg := parseTree(t, ubuntuTree(nil), ParseOptions{StaticModules: debianStatic})
	for _, d := range cfg.Dirs {
		assert.NotEqual(t, "/usr/lib/cgi-bin", d.Path)
	}
	_, ok := ParamValue(cfg.Params, "ScriptAlias")
	assert.False(t, ok)

	// Enabling mod_cgid defines the variable and brings the block in.
	files := ubuntuTree(map[string]string{
		"/etc/apache2/mods-enabled/cgid.load": "LoadModule cgid_module /usr/lib/apache2/modules/mod_cgid.so\n",
	})
	cfg = parseTree(t, files, ParseOptions{StaticModules: debianStatic})
	require.Len(t, cfg.Dirs, 1)
	assert.Equal(t, "/usr/lib/cgi-bin", cfg.Dirs[0].Path)
	assert.Equal(t, "+ExecCGI -MultiViews +SymLinksIfOwnerMatch", cfg.Dirs[0].Options)
}

// The sweep's flip fragment: hardening guarded by a module that is not loaded
// is not applied, so Apache keeps sending the OS banner and no header.
func TestConditional_NonexistentModuleBlockIsSkipped(t *testing.T) {
	files := ubuntuTree(map[string]string{
		"/etc/apache2/conf-enabled/security.conf": "ServerTokens OS\nTraceEnable On\n",
		"/etc/apache2/conf-enabled/zz-sweep-flip.conf": `<IfModule mod_nonexistent_sweep.c>
  Header always set X-Sweep-Guarded "DENY"
  ServerTokens Prod
  TraceEnable Off
</IfModule>
`,
	})
	cfg := parseTree(t, files, ParseOptions{StaticModules: debianStatic})
	assert.Equal(t, "OS", cfg.Params["ServerTokens"])
	assert.Equal(t, "On", cfg.Params["TraceEnable"])
	assert.NotContains(t, cfg.Headers, "X-Sweep-Guarded")
}

// IfModule matches the module identifier and the source file name, for
// modules loaded with LoadModule and for modules compiled into the binary.
func TestConditional_ModuleNameForms(t *testing.T) {
	files := ubuntuTree(map[string]string{
		"/etc/apache2/conf-enabled/forms.conf": `<IfModule headers_module>
	A1 yes
</IfModule>
<IfModule mod_headers.c>
	A2 yes
</IfModule>
<IfModule log_config_module>
	A3 yes
</IfModule>
<IfModule mod_log_config.c>
	A4 yes
</IfModule>
<IfModule http_module>
	A5 yes
</IfModule>
<IfModule !mod_rewrite.c>
	A6 yes
</IfModule>
<IfModule !mod_headers.c>
	B1 no
</IfModule>
<IfModule mod_rewrite.c>
	B2 no
</IfModule>
<IfModule MOD_HEADERS.C>
	B3 no
</IfModule>
`,
	})
	cfg := parseTree(t, files, ParseOptions{StaticModules: debianStatic})
	for _, k := range []string{"A1", "A2", "A3", "A4", "A5", "A6"} {
		assert.Equal(t, "yes", cfg.Params[k], k)
	}
	for _, k := range []string{"B1", "B2", "B3"} {
		assert.NotContains(t, cfg.Params, k)
	}

	// Without the static set, log_config_module is not known to be loaded.
	cfg = parseTree(t, files, ParseOptions{})
	assert.NotContains(t, cfg.Params, "A3")
}

// php8 ships as libphp8.x.so with identifier php_module and source name
// mod_php.c; Debian's php8.x.conf tests <IfModule mod_php.c>.
func TestConditional_SourceNameFromIdentifier(t *testing.T) {
	files := ubuntuTree(map[string]string{
		"/etc/apache2/mods-enabled/php8.3.load": "LoadModule php_module /usr/lib/apache2/modules/libphp8.3.so\n",
		"/etc/apache2/mods-enabled/php8.3.conf": "<IfModule mod_php.c>\n\tPhpSeen yes\n</IfModule>\n",
	})
	cfg := parseTree(t, files, ParseOptions{StaticModules: debianStatic})
	assert.Equal(t, "yes", cfg.Params["PhpSeen"])
}

// A module loaded after the <IfModule> test does not satisfy it: Apache
// evaluates the container when it reads it.
func TestConditional_EvaluatedInReadOrder(t *testing.T) {
	files := map[string]string{
		"/etc/apache2/apache2.conf": `<IfModule mod_headers.c>
	Early yes
</IfModule>
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
<IfModule mod_headers.c>
	Late yes
</IfModule>
`,
	}
	cfg := parseTree(t, files, ParseOptions{})
	assert.NotContains(t, cfg.Params, "Early")
	assert.Equal(t, "yes", cfg.Params["Late"])
}

func TestConditional_IfDefine(t *testing.T) {
	files := map[string]string{
		"/etc/apache2/apache2.conf": `Define LOCAL
<IfDefine LOCAL>
	A1 yes
</IfDefine>
<IfDefine !LOCAL>
	B1 no
</IfDefine>
<IfDefine FROM_CLI>
	A2 yes
</IfDefine>
<IfDefine APACHE_RUN_USER>
	B2 no
</IfDefine>
<IfDefine !NEVER>
	A3 yes
</IfDefine>
UnDefine LOCAL
<IfDefine LOCAL>
	B3 no
</IfDefine>
`,
	}
	fileContent := func(p string) (string, error) { return files[p], nil }
	// envvars are environment variables, not defines: IfDefine must not see them.
	cfg, err := ParseWithGlobOptions("/etc/apache2/apache2.conf", fileContent, nil,
		map[string]string{"APACHE_RUN_USER": "www-data"}, ParseOptions{Defines: []string{"FROM_CLI"}})
	require.NoError(t, err)
	for _, k := range []string{"A1", "A2", "A3"} {
		assert.Equal(t, "yes", cfg.Params[k], k)
	}
	for _, k := range []string{"B1", "B2", "B3"} {
		assert.NotContains(t, cfg.Params, k)
	}
}

// Conditional containers nested inside a VirtualHost or Directory are
// evaluated the same way.
func TestConditional_InsideVirtualHost(t *testing.T) {
	files := ubuntuTree(map[string]string{
		"/etc/apache2/sites-enabled/site.conf": `<VirtualHost *:443>
	ServerName a.example.com
	<IfModule mod_headers.c>
		Header always set X-Frame-Options "DENY"
	</IfModule>
	<IfModule mod_nonexistent.c>
		Header always set X-Phantom "1"
		SSLEngine on
	</IfModule>
	<Directory /srv/a>
		<IfModule mod_nonexistent.c>
			Options Indexes
		</IfModule>
		<IfModule mod_alias.c>
			Options None
		</IfModule>
	</Directory>
</VirtualHost>
`,
	})
	cfg := parseTree(t, files, ParseOptions{StaticModules: debianStatic})
	require.Len(t, cfg.VHosts, 1)
	assert.False(t, cfg.VHosts[0].SSL)
	assert.Contains(t, cfg.Headers, "X-Frame-Options")
	assert.NotContains(t, cfg.Headers, "X-Phantom")
	require.Len(t, cfg.Dirs, 1)
	assert.Equal(t, "None", cfg.Dirs[0].Options)
}

// Apache has no inline comments: `#` only starts a comment at the beginning
// of a line. mods-available/autoindex.conf ships this line, and Apache passes
// `*#` through as an argument (apache2ctl -t -D DUMP_CONFIG keeps it).
func TestParse_HashInsideArgumentIsNotAComment(t *testing.T) {
	cfg := Parse("IndexIgnore .??* *~ *# RCS CVS *,v *,t\n" +
		"  # indented comment\n" +
		"Header always set X-Note \"a # b\"\n")
	assert.Equal(t, ".??* *~ *# RCS CVS *,v *,t", cfg.Params["IndexIgnore"])
	assert.Equal(t, []string{"a # b"}, cfg.Headers["X-Note"])
	assert.Len(t, cfg.Params, 1)
}

func TestParseStaticModuleList(t *testing.T) {
	out := "Compiled in modules:\n  core.c\n  mod_so.c\n  mod_watchdog.c\n  http_core.c\n  mod_log_config.c\n  mod_logio.c\n  mod_version.c\n  mod_unixd.c\n  mod_systemd.c\n"
	assert.Equal(t, []string{"core.c", "mod_so.c", "mod_watchdog.c", "http_core.c", "mod_log_config.c", "mod_logio.c", "mod_version.c", "mod_unixd.c", "mod_systemd.c"}, ParseStaticModuleList(out))
	assert.Empty(t, ParseStaticModuleList("apache2: command not found\n"))
	assert.Empty(t, ParseStaticModuleList(""))
}

func TestDefinesFromArguments(t *testing.T) {
	assert.Equal(t, []string{"SSL", "FOO"}, DefinesFromArguments("-D SSL -k start -DFOO"))
	assert.Empty(t, DefinesFromArguments(""))
	assert.Empty(t, DefinesFromArguments(strings.Repeat(" ", 3)+"-k start"))
}
