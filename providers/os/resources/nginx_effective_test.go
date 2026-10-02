// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/nginx"
)

// sweepTLSConf is the file the live verification drops into conf.d (or
// sites-enabled) next to each distribution's stock configuration: an
// http-level add_header, a TLS server that sets no ssl_protocols, and a
// plain server with an add_header of its own.
const sweepTLSConf = `
add_header X-Frame-Options DENY always;
server {
    listen 8443 ssl;
    server_name tls.example.test;
    ssl_certificate /etc/nginx/tls.pem;
    ssl_certificate_key /etc/nginx/tls.key;
    location / { }
}
server {
    listen 8081;
    server_name own-header.example.test;
    root /srv/own;
    add_header X-Own yes;
    location /sub/ { }
}
`

// parseNginxFixture parses root with includes resolved from files, a map of
// absolute path to content (a value starting with "testdata:" is read from
// testdata/nginx).
func parseNginxFixture(t *testing.T, root string, files map[string]string) []nginx.Directive {
	t.Helper()
	fs := afero.NewMemMapFs()
	for path, content := range files {
		if name, ok := strings.CutPrefix(content, "testdata:"); ok {
			data, err := os.ReadFile(filepath.Join("testdata", "nginx", name))
			require.NoError(t, err)
			content = string(data)
		}
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}
	afs := &afero.Afero{Fs: fs}
	open := func(path string) (io.ReadCloser, error) { return fs.Open(path) }
	glob := func(pattern string) ([]string, error) { return afero.Glob(afs, pattern) }
	cfg, err := nginx.ParseFiles(root, open, glob)
	require.NoError(t, err)
	return cfg.Directives
}

func nginxServerByName(t *testing.T, servers []nginxServer, name string) nginxServer {
	t.Helper()
	for _, s := range servers {
		if s.ServerName == name {
			return s
		}
	}
	require.Failf(t, "server not found", "no server named %q", name)
	return nginxServer{}
}

// Debian 13's stock nginx.conf sets ssl_protocols TLSv1.2 TLSv1.3,
// ssl_prefer_server_ciphers off and server_tokens off in http{}. A server
// that sets none of them runs with those values.
// Fails if resolveNginxServer reads srv.scope instead of parent.child(srv.scope).
func TestNginxServerInheritsHTTPDebian13(t *testing.T) {
	dirs := parseNginxFixture(t, "/etc/nginx/nginx.conf", map[string]string{
		"/etc/nginx/nginx.conf":               "testdata:debian13-nginx.conf",
		"/etc/nginx/sites-enabled/default":    "testdata:ubuntu2404-sites-default", // identical on Debian 13
		"/etc/nginx/conf.d/zz-sweep-tls.conf": sweepTLSConf,
		"/etc/nginx/mime.types":               "",
	})
	w := walkNginxConfig(dirs, "1.26.3")

	tls := nginxServerByName(t, w.servers, "tls.example.test")
	assert.Equal(t, "TLSv1.2 TLSv1.3", tls.SSLProtocols)
	assert.Equal(t, "off", tls.ServerTokens)
	assert.False(t, tls.SSLPreferServerCiphers)
	assert.Equal(t, "/etc/nginx/tls.pem", tls.SSLCertificate)
	assert.True(t, tls.SSL)
	// params stays what the server block itself says
	assert.NotContains(t, tls.Params, "ssl_protocols")
	assert.NotContains(t, tls.Params, "server_tokens")

	// the stock default server takes the same http values
	def := nginxServerByName(t, w.servers, "_")
	assert.Equal(t, "TLSv1.2 TLSv1.3", def.SSLProtocols)
	assert.Equal(t, "/var/www/html", def.Root)
	assert.False(t, def.SSL)
}

// Ubuntu 24.04's stock http{} enables TLSv1 and TLSv1.1 and prefers server
// ciphers. A check that no server allows TLSv1.1 must see them.
func TestNginxServerInheritsHTTPUbuntu2404(t *testing.T) {
	dirs := parseNginxFixture(t, "/etc/nginx/nginx.conf", map[string]string{
		"/etc/nginx/nginx.conf":               "testdata:ubuntu2404-nginx.conf",
		"/etc/nginx/sites-enabled/default":    "testdata:ubuntu2404-sites-default",
		"/etc/nginx/conf.d/zz-sweep-tls.conf": sweepTLSConf,
		"/etc/nginx/mime.types":               "",
	})
	// an unknown version would also give TLSv1.1 by default, so use one
	// whose default does not
	w := walkNginxConfig(dirs, "1.27.3")

	tls := nginxServerByName(t, w.servers, "tls.example.test")
	assert.Equal(t, "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3", tls.SSLProtocols)
	assert.True(t, tls.SSLPreferServerCiphers)
	// server_tokens is commented out in the stock file
	assert.Equal(t, "on", tls.ServerTokens)
}

// add_header is inherited all or nothing: a server with no add_header gets
// every http-level one, a server with its own gets only its own.
// Fails if nginxScope.child merges own and parent headers by default.
func TestNginxAddHeaderAllOrNothing(t *testing.T) {
	dirs, err := nginx.Parse(`
http {
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff;
    server { server_name inherits; }
    server { server_name own; add_header X-Own yes; }
    server { server_name merge; add_header_inherit merge; add_header X-Own yes; }
    server { server_name off; add_header_inherit off; }
}`)
	require.NoError(t, err)
	w := walkNginxConfig(dirs, "1.29.3")

	assert.Equal(t, map[string][]string{
		"X-Frame-Options":        {"DENY always"},
		"X-Content-Type-Options": {"nosniff"},
	}, nginxServerByName(t, w.servers, "inherits").AddHeaders)
	assert.Equal(t, map[string][]string{"X-Own": {"yes"}}, nginxServerByName(t, w.servers, "own").AddHeaders)
	assert.Equal(t, map[string][]string{
		"X-Frame-Options":        {"DENY always"},
		"X-Content-Type-Options": {"nosniff"},
		"X-Own":                  {"yes"},
	}, nginxServerByName(t, w.servers, "merge").AddHeaders)
	assert.Empty(t, nginxServerByName(t, w.servers, "off").AddHeaders)
}

// A directive the server sets wins over the http one, in either order of
// appearance; a location inherits root from its server, which inherits it
// from http.
// Fails if child copies own values before parent values.
func TestNginxServerOverrideAndLocationRoot(t *testing.T) {
	dirs, err := nginx.Parse(`
http {
    root /srv/http;
    server {
        server_name override;
        ssl_protocols TLSv1.3;
        ssl_session_tickets off;
        server_tokens build;
        location / { }
        location /own/ { root /srv/own; }
    }
    server {
        server_name plain;
        location / { }
    }
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_session_timeout 1d;
}`)
	require.NoError(t, err)
	w := walkNginxConfig(dirs, "1.24.0")

	o := nginxServerByName(t, w.servers, "override")
	assert.Equal(t, "TLSv1.3", o.SSLProtocols)
	assert.Equal(t, "off", o.SSLSessionTickets)
	assert.Equal(t, "1d", o.SSLSessionTimeout)
	assert.Equal(t, "build", o.ServerTokens)
	assert.Equal(t, "/srv/http", o.Root)
	require.Len(t, o.Locations, 2)
	assert.Equal(t, "/srv/http", o.Locations[0].Root)
	assert.Equal(t, "/srv/own", o.Locations[1].Root)
	assert.NotContains(t, o.Locations[0].Params, "root")

	p := nginxServerByName(t, w.servers, "plain")
	assert.Equal(t, "TLSv1.1 TLSv1.2", p.SSLProtocols)
	assert.Equal(t, "/srv/http", p.Locations[0].Root)
}

// stream servers inherit the ssl_* directives of stream{}, not of http{},
// and have no server_tokens.
// Fails if walkNginxConfig resolves stream servers against httpScope.
func TestNginxStreamServerInherits(t *testing.T) {
	dirs, err := nginx.Parse(`
http { ssl_protocols TLSv1.2; }
stream {
    ssl_protocols TLSv1.3;
    ssl_session_tickets off;
    server { listen 5432 ssl; ssl_certificate /etc/ssl/db.pem; proxy_pass db; }
    server { listen 5433 ssl; ssl_protocols TLSv1.2 TLSv1.3; proxy_pass db; }
}`)
	require.NoError(t, err)
	w := walkNginxConfig(dirs, "1.26.3")

	require.Len(t, w.streamServers, 2)
	assert.Equal(t, "TLSv1.3", w.streamServers[0].SSLProtocols)
	assert.Equal(t, "off", w.streamServers[0].SSLSessionTickets)
	assert.Equal(t, "", w.streamServers[0].ServerTokens)
	assert.Equal(t, "TLSv1.2 TLSv1.3", w.streamServers[1].SSLProtocols)
}

// With nothing set anywhere, the server reports nginx's defaults for the
// installed version. Rocky 8 ships nginx 1.14.1, Fedora 44 ships 1.30.5;
// neither stock nginx.conf sets any of these directives.
// Fails if a threshold in nginxDefaultSSLProtocols or a default in
// resolveNginxServer changes.
func TestNginxServerDefaultsStock(t *testing.T) {
	for _, tc := range []struct {
		fixture, version, protocols string
	}{
		{"rocky8-nginx.conf", "1.14.1", "TLSv1 TLSv1.1 TLSv1.2"},
		{"fedora44-nginx.conf", "1.30.5", "TLSv1.2 TLSv1.3"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			dirs := parseNginxFixture(t, "/etc/nginx/nginx.conf", map[string]string{
				"/etc/nginx/nginx.conf":               "testdata:" + tc.fixture,
				"/etc/nginx/conf.d/zz-sweep-tls.conf": sweepTLSConf,
				"/etc/nginx/mime.types":               "",
			})
			w := walkNginxConfig(dirs, tc.version)
			tls := nginxServerByName(t, w.servers, "tls.example.test")
			assert.Equal(t, tc.protocols, tls.SSLProtocols)
			assert.Equal(t, "on", tls.ServerTokens)
			assert.Equal(t, "on", tls.SSLSessionTickets)
			assert.Equal(t, "5m", tls.SSLSessionTimeout)
			assert.False(t, tls.SSLPreferServerCiphers)
			assert.Equal(t, "", tls.SSLCiphers)
			assert.Equal(t, map[string][]string{"X-Frame-Options": {"DENY always"}}, tls.AddHeaders)

			own := nginxServerByName(t, w.servers, "own-header.example.test")
			assert.Equal(t, map[string][]string{"X-Own": {"yes"}}, own.AddHeaders)
			assert.Equal(t, "/srv/own", own.Locations[0].Root)
		})
	}
}

func TestNginxDefaultSSLProtocols(t *testing.T) {
	for version, want := range map[string]string{
		"1.8.1":  "SSLv3 TLSv1 TLSv1.1 TLSv1.2",
		"1.9.1":  "TLSv1 TLSv1.1 TLSv1.2",
		"1.14.1": "TLSv1 TLSv1.1 TLSv1.2",
		"1.21.5": "TLSv1 TLSv1.1 TLSv1.2",
		"1.23.3": "TLSv1 TLSv1.1 TLSv1.2",
		"1.23.4": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
		"1.24.0": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
		"1.27.2": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
		"1.27.3": "TLSv1.2 TLSv1.3",
		"1.30.5": "TLSv1.2 TLSv1.3",
		"2.0.0":  "TLSv1.2 TLSv1.3",
		// unknown: every protocol a release from 1.9.1 on may enable
		"":        "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
		"unknown": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
		"1.24":    "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
	} {
		assert.Equal(t, want, nginxDefaultSSLProtocols(version), version)
	}
}

// Fails if workerProcesses returns "" for an unset worker_processes.
func TestNginxWorkerProcessesDefault(t *testing.T) {
	c := &mqlNginxConf{}
	v, err := c.workerProcesses(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "1", v)
	v, err = c.workerProcesses(map[string]any{"worker_processes": "auto"})
	require.NoError(t, err)
	assert.Equal(t, "auto", v)
}

// The -g directives of the running master count only for the file it loads.
// Fails if nginxGlobalDirectives drops the path comparison.
func TestNginxGlobalDirectives(t *testing.T) {
	launch := nginxLaunch{conf: "/etc/nginx/nginx.conf", globals: "worker_processes 3; daemon on;"}
	globals := nginxGlobalDirectives(launch, "/etc/nginx/nginx.conf")
	require.Len(t, globals, 2)

	dirs := parseNginxFixture(t, "/etc/nginx/nginx.conf", map[string]string{
		"/etc/nginx/nginx.conf": "testdata:sles16-nginx.conf",
	})
	w := walkNginxConfig(append(globals, dirs...), "1.27.2")
	assert.Equal(t, "3", w.params["worker_processes"])

	assert.Nil(t, nginxGlobalDirectives(launch, "/etc/nginx-alt/nginx.conf"))
}

const nginxTestBuildOutput = "nginx version: nginx/1.24.0\n" +
	"configure arguments: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/run/nginx.pid\n"

func TestResolveNginxLaunch(t *testing.T) {
	build := func(string) string { return nginxTestBuildOutput }
	noBuild := func(string) string { return "" }
	const platformDefault = "/usr/local/etc/nginx/nginx.conf"

	newFS := func(files map[string]string) *afero.Afero {
		fs := afero.NewMemMapFs()
		for p, c := range files {
			require.NoError(t, afero.WriteFile(fs, p, []byte(c), 0o644))
		}
		return &afero.Afero{Fs: fs}
	}

	// Fails if the master's -c is ignored.
	t.Run("running master with -c and -g", func(t *testing.T) {
		afs := newFS(map[string]string{
			"/run/nginx.pid":     "4242\n",
			"/proc/4242/cmdline": "nginx: master process /usr/sbin/nginx -c /etc/nginx-alt/nginx.conf -g worker_processes 3;\x00",
		})
		got := resolveNginxLaunch(afs, build, platformDefault)
		assert.Equal(t, nginxLaunch{conf: "/etc/nginx-alt/nginx.conf", globals: "worker_processes 3;"}, got)
	})

	// The pid directive of the default configuration names the pid file.
	// Fails if nginxPidDirective is not consulted.
	t.Run("pid file from the configuration", func(t *testing.T) {
		afs := newFS(map[string]string{
			"/etc/nginx/nginx.conf": "pid /run/nginx-custom.pid;\nevents {}\n",
			"/run/nginx-custom.pid": "77",
			"/proc/77/cmdline":      "/usr/sbin/nginx\x00-c\x00/srv/nginx.conf\x00",
		})
		got := resolveNginxLaunch(afs, build, platformDefault)
		assert.Equal(t, "/srv/nginx.conf", got.conf)
	})

	// Fails if the build's conf path is skipped when nginx is not running.
	t.Run("stopped: build conf path", func(t *testing.T) {
		got := resolveNginxLaunch(newFS(nil), build, platformDefault)
		assert.Equal(t, nginxLaunch{conf: "/etc/nginx/nginx.conf"}, got)
	})

	t.Run("stale pid file", func(t *testing.T) {
		afs := newFS(map[string]string{
			"/run/nginx.pid":     "4242",
			"/proc/4242/cmdline": "/usr/sbin/sshd\x00-D\x00",
		})
		got := resolveNginxLaunch(afs, build, platformDefault)
		assert.Equal(t, nginxLaunch{conf: "/etc/nginx/nginx.conf"}, got)
	})

	t.Run("no nginx binary: platform default", func(t *testing.T) {
		got := resolveNginxLaunch(newFS(nil), noBuild, platformDefault)
		assert.Equal(t, nginxLaunch{conf: platformDefault}, got)
	})

	// The master runs another binary than the one on the PATH. Fails if the
	// master's own -V is not read.
	t.Run("master binary with its own build", func(t *testing.T) {
		afs := newFS(map[string]string{
			"/run/nginx.pid":  "9",
			"/proc/9/cmdline": "nginx: master process /opt/nginx/sbin/nginx -p /opt/nginx/\x00",
		})
		got := resolveNginxLaunch(afs, func(bin string) string {
			if bin == "/opt/nginx/sbin/nginx" {
				return "nginx version: nginx/1.27.0\nconfigure arguments: --with-http_ssl_module\n"
			}
			return nginxTestBuildOutput
		}, platformDefault)
		assert.Equal(t, "/opt/nginx/conf/nginx.conf", got.conf)
	})
}
