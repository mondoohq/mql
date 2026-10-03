// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const basicConfig = `
# Basic Apache configuration
ServerRoot "/etc/httpd"
ServerName www.example.com
ServerAdmin admin@example.com
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User apache
Group apache

Listen 80
Listen 443

DocumentRoot "/var/www/html"

LogLevel warn
ErrorLog "logs/error_log"

LoadModule ssl_module modules/mod_ssl.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule headers_module modules/mod_headers.so
`

func TestParseBasicDirectives(t *testing.T) {
	cfg := Parse(basicConfig)
	require.NotNil(t, cfg)

	assert.Equal(t, "www.example.com", cfg.Params["ServerName"])
	assert.Equal(t, "admin@example.com", cfg.Params["ServerAdmin"])
	assert.Equal(t, "Prod", cfg.Params["ServerTokens"])
	assert.Equal(t, "Off", cfg.Params["ServerSignature"])
	assert.Equal(t, "Off", cfg.Params["TraceEnable"])
	assert.Equal(t, "60", cfg.Params["Timeout"])
	assert.Equal(t, "On", cfg.Params["KeepAlive"])
	assert.Equal(t, "apache", cfg.Params["User"])
	assert.Equal(t, "apache", cfg.Params["Group"])
	assert.Equal(t, "warn", cfg.Params["LogLevel"])
	assert.Equal(t, "/var/www/html", cfg.Params["DocumentRoot"])
}

func TestParseListenDirectives(t *testing.T) {
	cfg := Parse(basicConfig)
	require.NotNil(t, cfg)

	// Listen is a multi-param, so both values are comma-joined
	assert.Equal(t, "80,443", cfg.Params["Listen"])
}

func TestParseModules(t *testing.T) {
	cfg := Parse(basicConfig)
	require.NotNil(t, cfg)

	require.Len(t, cfg.Modules, 3)
	assert.Equal(t, "ssl_module", cfg.Modules[0].Name)
	assert.Equal(t, "modules/mod_ssl.so", cfg.Modules[0].Path)
	assert.Equal(t, "rewrite_module", cfg.Modules[1].Name)
	assert.Equal(t, "headers_module", cfg.Modules[2].Name)
}

const virtualHostConfig = `
ServerName default.example.com

<VirtualHost *:80>
    ServerName http.example.com
    DocumentRoot /var/www/http
    Redirect permanent / https://http.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName secure.example.com
    DocumentRoot /var/www/secure
    SSLEngine on
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLCertificateFile /etc/pki/tls/certs/server.crt
    SSLCertificateKeyFile /etc/pki/tls/private/server.key
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options DENY
</VirtualHost>
`

func TestParseVirtualHosts(t *testing.T) {
	cfg := Parse(virtualHostConfig)
	require.NotNil(t, cfg)

	require.Len(t, cfg.VHosts, 2)

	// HTTP VHost
	http := cfg.VHosts[0]
	assert.Equal(t, "*:80", http.Address)
	assert.Equal(t, "http.example.com", http.ServerName)
	assert.Equal(t, "/var/www/http", http.DocumentRoot)
	assert.False(t, http.SSL)

	// HTTPS VHost
	https := cfg.VHosts[1]
	assert.Equal(t, "*:443", https.Address)
	assert.Equal(t, "secure.example.com", https.ServerName)
	assert.Equal(t, "/var/www/secure", https.DocumentRoot)
	assert.True(t, https.SSL)
	assert.Equal(t, "all -SSLv3 -TLSv1 -TLSv1.1", https.Params["SSLProtocol"])
	assert.Equal(t, "HIGH:!aNULL:!MD5", https.Params["SSLCipherSuite"])
}

const directoryConfig = `
<Directory />
    AllowOverride none
    Require all denied
    Options None
</Directory>

<Directory "/var/www/html">
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

<Directory "/var/www/cgi-bin">
    Options +ExecCGI
    AllowOverride None
    Require all granted
</Directory>
`

func TestParseDirectories(t *testing.T) {
	cfg := Parse(directoryConfig)
	require.NotNil(t, cfg)

	require.Len(t, cfg.Dirs, 3)

	root := cfg.Dirs[0]
	assert.Equal(t, "/", root.Path)
	assert.Equal(t, "None", root.Options)
	assert.Equal(t, "none", root.AllowOverride)
	assert.Equal(t, "all denied", root.Params["Require"])

	html := cfg.Dirs[1]
	assert.Equal(t, "/var/www/html", html.Path)
	assert.Equal(t, "-Indexes +FollowSymLinks", html.Options)
	assert.Equal(t, "None", html.AllowOverride)

	cgi := cfg.Dirs[2]
	assert.Equal(t, "/var/www/cgi-bin", cgi.Path)
	assert.Equal(t, "+ExecCGI", cgi.Options)
}

const includeConfig = `
ServerRoot "/etc/httpd"
Include conf.d/*.conf
IncludeOptional sites-enabled/*.conf
`

func TestParseIncludes(t *testing.T) {
	cfg := Parse(includeConfig)
	require.NotNil(t, cfg)

	require.Len(t, cfg.Includes, 2)
	assert.Equal(t, "conf.d/*.conf", cfg.Includes[0])
	assert.Equal(t, "sites-enabled/*.conf", cfg.Includes[1])
}

func TestParseComments(t *testing.T) {
	content := `
# This is a comment
ServerName example.com
	# An indented comment
# Another comment
Timeout 30
`
	cfg := Parse(content)
	require.NotNil(t, cfg)

	assert.Equal(t, "example.com", cfg.Params["ServerName"])
	assert.Equal(t, "30", cfg.Params["Timeout"])
}

func TestParseContinuationLines(t *testing.T) {
	content := `SSLCipherSuite HIGH:MEDIUM:\
!aNULL:!MD5
Timeout 30
`
	cfg := Parse(content)
	require.NotNil(t, cfg)

	assert.Equal(t, "HIGH:MEDIUM: !aNULL:!MD5", cfg.Params["SSLCipherSuite"])
	assert.Equal(t, "30", cfg.Params["Timeout"])
}

func TestParseQuotedValues(t *testing.T) {
	content := `
DocumentRoot "/var/www/my site"
ErrorLog "logs/error_log"
`
	cfg := Parse(content)
	require.NotNil(t, cfg)

	assert.Equal(t, "/var/www/my site", cfg.Params["DocumentRoot"])
	assert.Equal(t, "logs/error_log", cfg.Params["ErrorLog"])
}

func TestParseWithGlob(t *testing.T) {
	files := map[string]string{
		"/etc/httpd/conf/httpd.conf": `
ServerRoot "/etc/httpd"
ServerName main.example.com
Include conf.d/*.conf
`,
		"/etc/httpd/conf.d/ssl.conf": `
SSLProtocol all -SSLv3
SSLCipherSuite HIGH:!aNULL
`,
		"/etc/httpd/conf.d/security.conf": `
ServerTokens Prod
ServerSignature Off
`,
	}

	fileContent := func(path string) (string, error) {
		if c, ok := files[path]; ok {
			return c, nil
		}
		return "", &fileNotFoundError{path: path}
	}

	globExpand := func(pattern string) ([]string, error) {
		if pattern == "conf.d/*.conf" {
			return []string{"/etc/httpd/conf.d/ssl.conf", "/etc/httpd/conf.d/security.conf"}, nil
		}
		return nil, nil
	}

	cfg, err := ParseWithGlob("/etc/httpd/conf/httpd.conf", fileContent, globExpand, nil)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "main.example.com", cfg.Params["ServerName"])
	assert.Equal(t, "all -SSLv3", cfg.Params["SSLProtocol"])
	assert.Equal(t, "Prod", cfg.Params["ServerTokens"])
	assert.Equal(t, "Off", cfg.Params["ServerSignature"])
}

func TestParseWithGlobIncludeCycle(t *testing.T) {
	// Two files that include each other (and the root re-including itself) must
	// not recurse forever — the visited guard breaks the cycle.
	files := map[string]string{
		"/etc/httpd/conf/httpd.conf": `
ServerName main.example.com
Include conf.d/a.conf
`,
		"/etc/httpd/conf.d/a.conf": `
ServerTokens Prod
Include conf.d/b.conf
`,
		"/etc/httpd/conf.d/b.conf": `
ServerSignature Off
Include conf.d/a.conf
Include conf/httpd.conf
`,
	}

	fileContent := func(path string) (string, error) {
		if c, ok := files[path]; ok {
			return c, nil
		}
		return "", &fileNotFoundError{path: path}
	}
	globExpand := func(pattern string) ([]string, error) {
		switch pattern {
		case "conf.d/a.conf":
			return []string{"/etc/httpd/conf.d/a.conf"}, nil
		case "conf.d/b.conf":
			return []string{"/etc/httpd/conf.d/b.conf"}, nil
		case "conf/httpd.conf":
			return []string{"/etc/httpd/conf/httpd.conf"}, nil
		}
		return nil, nil
	}

	var cfg *Config
	var err error
	require.NotPanics(t, func() {
		cfg, err = ParseWithGlob("/etc/httpd/conf/httpd.conf", fileContent, globExpand, nil)
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	// Each file is still parsed exactly once.
	assert.Equal(t, "main.example.com", cfg.Params["ServerName"])
	assert.Equal(t, "Prod", cfg.Params["ServerTokens"])
	assert.Equal(t, "Off", cfg.Params["ServerSignature"])
}

func TestParseVirtualHostNestedBlocks(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html
    SSLEngine on
    <Directory /var/www/html>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <Location /status>
        SetHandler server-status
    </Location>
    Header always set X-Frame-Options DENY
</VirtualHost>
`
	cfg := Parse(content)
	require.NotNil(t, cfg)
	require.Len(t, cfg.VHosts, 1)

	vh := cfg.VHosts[0]
	assert.Equal(t, "example.com", vh.ServerName)
	assert.Equal(t, "/var/www/html", vh.DocumentRoot)
	assert.True(t, vh.SSL)

	// Nested block directives must NOT leak into VirtualHost params
	assert.NotContains(t, vh.Params, "Options")
	assert.NotContains(t, vh.Params, "AllowOverride")
	assert.NotContains(t, vh.Params, "Require")
	assert.NotContains(t, vh.Params, "SetHandler")

	// VirtualHost's own directives must still be present
	assert.Contains(t, vh.Params, "Header")
}

func TestParseDirectoryNestedBlocks(t *testing.T) {
	content := `
<Directory /var/www>
    Options Indexes
    <Files "*.php">
        SetHandler application/x-httpd-php
    </Files>
    AllowOverride All
</Directory>
`
	cfg := Parse(content)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Dirs, 1)

	d := cfg.Dirs[0]
	assert.Equal(t, "Indexes", d.Options)
	assert.Equal(t, "All", d.AllowOverride)

	// Nested <Files> directives must NOT leak
	assert.NotContains(t, d.Params, "SetHandler")
}

func TestParseEmptyContent(t *testing.T) {
	cfg := Parse("")
	require.NotNil(t, cfg)
	assert.Empty(t, cfg.Params)
	assert.Empty(t, cfg.Modules)
	assert.Empty(t, cfg.VHosts)
	assert.Empty(t, cfg.Dirs)
}

type fileNotFoundError struct {
	path string
}

func (e *fileNotFoundError) Error() string {
	return "file not found: " + e.path
}

// New tests for the TLS / hardening / Location / ServerAlias / Redirect surface.

const tlsVHostConfig = `
<VirtualHost *:443>
  ServerName secure.example.com
  ServerAlias www.secure.example.com api.secure.example.com
  ServerAlias alt.secure.example.com
  DocumentRoot /var/www/secure

  SSLEngine on
  SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
  SSLCipherSuite HIGH:!aNULL:!MD5
  SSLHonorCipherOrder on
  SSLCertificateFile /etc/ssl/certs/server.crt
  SSLCertificateKeyFile /etc/ssl/private/server.key
  SSLCertificateChainFile /etc/ssl/certs/chain.crt

  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
  Header always set X-Frame-Options DENY

  Redirect permanent /old /new
  RedirectMatch 301 ^/legacy/(.*)$ /v2/$1

  <Location "/admin">
    AuthType Basic
    AuthName "Restricted"
    Require valid-user
    Require ip 10.0.0.0/8
  </Location>
</VirtualHost>

Header always set X-Top-Header "top-value"

<LocationMatch "^/secret/.*$">
  AuthType Basic
  AuthName "Secret area"
  Require valid-user
</LocationMatch>
`

func TestParseVirtualHostTLSFields(t *testing.T) {
	cfg := Parse(tlsVHostConfig)
	require.Len(t, cfg.VHosts, 1)
	vh := cfg.VHosts[0]

	assert.Equal(t, "secure.example.com", vh.ServerName)
	assert.Equal(t, []string{"www.secure.example.com", "api.secure.example.com", "alt.secure.example.com"}, vh.ServerAliases,
		"multiple ServerAlias args + multiple ServerAlias lines must accumulate")
	assert.True(t, vh.SSL, "SSLEngine on must set SSL")
	assert.Equal(t, "all -SSLv3 -TLSv1 -TLSv1.1", vh.SSLProtocol)
	assert.Equal(t, "HIGH:!aNULL:!MD5", vh.SSLCipherSuite)
	assert.True(t, vh.SSLHonorCipherOrder)
	assert.Equal(t, "/etc/ssl/certs/server.crt", vh.SSLCertificateFile)
	assert.Equal(t, "/etc/ssl/private/server.key", vh.SSLCertificateKeyFile)
	assert.Equal(t, "/etc/ssl/certs/chain.crt", vh.SSLCertificateChainFile)
}

func TestParseVirtualHostRedirects(t *testing.T) {
	cfg := Parse(tlsVHostConfig)
	require.Len(t, cfg.VHosts, 1)
	vh := cfg.VHosts[0]
	require.Len(t, vh.Redirects, 2)

	r0 := vh.Redirects[0]
	assert.Equal(t, "Redirect", r0.Type)
	assert.Equal(t, "permanent", r0.Status)
	assert.Equal(t, "/old", r0.Match)
	assert.Equal(t, "/new", r0.Target)

	r1 := vh.Redirects[1]
	assert.Equal(t, "RedirectMatch", r1.Type)
	assert.Equal(t, "301", r1.Status)
	assert.Equal(t, `^/legacy/(.*)$`, r1.Match)
	assert.Equal(t, `/v2/$1`, r1.Target)
}

func TestParseLocationBlocks(t *testing.T) {
	cfg := Parse(tlsVHostConfig)
	// Both top-level <Location> AND nested <Location> inside the VHost must
	// surface in cfg.Locations.
	require.Len(t, cfg.Locations, 2)

	// Order is parse-discovery order: vhost-nested first, then top-level.
	nested := cfg.Locations[0]
	assert.Equal(t, "/admin", nested.Path)
	assert.False(t, nested.IsMatch)
	assert.Equal(t, "Basic", nested.AuthType)
	assert.Equal(t, "Restricted", nested.AuthName, "AuthName quotes must be stripped")
	assert.Equal(t, []string{"valid-user", "ip 10.0.0.0/8"}, nested.Require,
		"multiple Require lines must accumulate in order")

	top := cfg.Locations[1]
	assert.True(t, top.IsMatch, "<LocationMatch> must set IsMatch=true")
	assert.Equal(t, "^/secret/.*$", top.Path)
}

func TestParseSecurityHeaders(t *testing.T) {
	cfg := Parse(tlsVHostConfig)
	require.NotNil(t, cfg.Headers)

	// Both the VHost-scoped Header directives and the top-level one must
	// collect into the same map.
	assert.Equal(t,
		[]string{"max-age=63072000; includeSubDomains"},
		cfg.Headers["Strict-Transport-Security"])
	assert.Equal(t, []string{"DENY"}, cfg.Headers["X-Frame-Options"])
	assert.Equal(t, []string{"top-value"}, cfg.Headers["X-Top-Header"])

	// `Header set ...` (without `always`) must be ignored — only the
	// always-set rule survives every response path.
	cfg2 := Parse(`Header set X-Sometimes "v"`)
	assert.Empty(t, cfg2.Headers, "non-always `Header set` should not be collected")
}

func TestParseDirectoryRequire(t *testing.T) {
	cfg := Parse(`
<Directory /var/www>
  Options Indexes FollowSymLinks
  AllowOverride None
  Require all granted
  Require ip 192.168.0.0/16
</Directory>
`)
	require.Len(t, cfg.Dirs, 1)
	d := cfg.Dirs[0]
	assert.Equal(t, "Indexes FollowSymLinks", d.Options)
	assert.Equal(t, "None", d.AllowOverride)
	assert.Equal(t, []string{"all granted", "ip 192.168.0.0/16"}, d.Require)
}

func TestParseHeaderAlwaysSet(t *testing.T) {
	tests := []struct {
		arg       string
		wantName  string
		wantValue string
		wantOK    bool
	}{
		{`always set X-Frame-Options DENY`, "X-Frame-Options", "DENY", true},
		{`always set Strict-Transport-Security "max-age=63072000; includeSubDomains"`,
			"Strict-Transport-Security", "max-age=63072000; includeSubDomains", true},
		{`set X-Foo Bar`, "", "", false},
		{`always unset X-Foo`, "", "", false},
		{`always set X-Foo`, "", "", false}, // missing value
	}
	for _, tc := range tests {
		t.Run(tc.arg, func(t *testing.T) {
			name, val, ok := parseHeaderAlwaysSet(tc.arg)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantValue, val)
		})
	}
}

// mod_version's <IfVersion [[!]operator] version>, against httpd 2.4.62 (RHEL 9).
func TestIfVersionHolds(t *testing.T) {
	for _, tt := range []struct {
		arg  string
		want bool
	}{
		{"< 2.0", false},
		{">= 2.4", true},
		{"> 2.4", true}, // 2.4 reads as 2.4.0
		{"> 2.4.62", false},
		{">= 2.4.62", true},
		{"<= 2.4.61", false},
		{"2.4.62", true},
		{"= 2.4.62", true},
		{"== 2.4", false},
		{"!= 2.4.62", false},
		{"!< 2.0", true},
		{"!>= 2.4", false},
		{"= /^2\\.4\\./", true},
		{"/^2\\.2\\./", false},
		{"~ ^2\\.4", true},
		{"!~ ^2\\.4", false},
		{"2", false}, // 2 reads as 2.0.0
		{"> 2", true},
	} {
		st := newParseState(nil, nil, nil, ParseOptions{Version: "2.4.62"})
		assert.Equalf(t, tt.want, st.holds("IfVersion", tt.arg), "<IfVersion %s>", tt.arg)
	}

	t.Run("without a known version the contents apply", func(t *testing.T) {
		st := newParseState(nil, nil, nil, ParseOptions{})
		assert.True(t, st.holds("IfVersion", "< 2.0"))
	})

	t.Run("an argument httpd would reject applies", func(t *testing.T) {
		st := newParseState(nil, nil, nil, ParseOptions{Version: "2.4.62"})
		assert.True(t, st.holds("IfVersion", "< 2.x"))
	})
}

func TestIfFileHolds(t *testing.T) {
	var asked []string
	exists := func(p string) bool {
		asked = append(asked, p)
		return p == "/etc/httpd/conf.d/ssl.conf" || p == "conf/httpd.conf"
	}
	st := newParseState(nil, nil, nil, ParseOptions{FileExists: exists})
	assert.False(t, st.holds("IfFile", "/nonexistent-sweep"))
	assert.True(t, st.holds("IfFile", "!/nonexistent-sweep"))
	assert.True(t, st.holds("IfFile", `"/etc/httpd/conf.d/ssl.conf"`))
	assert.False(t, st.holds("IfFile", "!/etc/httpd/conf.d/ssl.conf"))
	// a relative path is resolved by the caller against ServerRoot
	assert.True(t, st.holds("IfFile", "conf/httpd.conf"))
	assert.Equal(t, []string{"/nonexistent-sweep", "/nonexistent-sweep", "/etc/httpd/conf.d/ssl.conf", "/etc/httpd/conf.d/ssl.conf", "conf/httpd.conf"}, asked)

	t.Run("without a filesystem the contents apply", func(t *testing.T) {
		st := newParseState(nil, nil, nil, ParseOptions{})
		assert.True(t, st.holds("IfFile", "/nonexistent-sweep"))
	})
}

// The sweep's A14 fixture: ServerTokens set only inside a false <IfVersion>
// and a false <IfFile>; the server sends its full banner.
func TestParseIfVersionIfFile(t *testing.T) {
	files := map[string]string{
		"/etc/httpd/conf/httpd.conf": "ServerRoot \"/etc/httpd\"\nIncludeOptional conf.d/*.conf\n",
		"/etc/httpd/conf.d/zz-sweep-flip.conf": "<IfVersion < 2.0>\n  ServerTokens Prod\n</IfVersion>\n" +
			"<IfFile /nonexistent-sweep>\n  TraceEnable Off\n</IfFile>\n" +
			"<IfVersion >= 2.4>\n  ServerSignature On\n</IfVersion>\n",
	}
	fileContent := func(p string) (string, error) { return files[p], nil }
	glob := func(p string) ([]string, error) {
		if p == "conf.d/*.conf" {
			return []string{"/etc/httpd/conf.d/zz-sweep-flip.conf"}, nil
		}
		return []string{p}, nil
	}
	cfg, err := ParseWithGlobOptions("/etc/httpd/conf/httpd.conf", fileContent, glob, nil, ParseOptions{
		Version:    "2.4.62",
		FileExists: func(string) bool { return false },
	})
	require.NoError(t, err)
	assert.NotContains(t, cfg.Params, "ServerTokens")
	assert.NotContains(t, cfg.Params, "TraceEnable")
	assert.Equal(t, "On", cfg.Params["ServerSignature"])
}
