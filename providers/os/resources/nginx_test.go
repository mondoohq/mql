// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/resources/nginx"
	"go.mondoo.com/mql/v13/utils/syncx"
)

func TestParseNginxServerBlock(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "listen", Args: []string{"80"}},
		{Name: "listen", Args: []string{"443", "ssl"}},
		{Name: "server_name", Args: []string{"example.com", "www.example.com"}},
		{Name: "root", Args: []string{"/var/www/html"}},
		{Name: "ssl_certificate", Args: []string{"/etc/ssl/cert.pem"}},
		{Name: "ssl_certificate_key", Args: []string{"/etc/ssl/key.pem"}},
		{Name: "location", Args: []string{"/"}, Block: []nginx.Directive{
			{Name: "proxy_pass", Args: []string{"http://backend"}},
		}},
		{Name: "location", Args: []string{"/static"}, Block: []nginx.Directive{
			{Name: "root", Args: []string{"/var/www/static"}},
			{Name: "expires", Args: []string{"30d"}},
		}},
	}

	srv := parseNginxServerBlock(directives)
	assert.Equal(t, "example.com www.example.com", srv.ServerName)
	assert.Equal(t, "80,443 ssl", srv.Listen)
	assert.Equal(t, "/var/www/html", srv.Root)
	assert.True(t, srv.SSL)
	assert.Equal(t, "/etc/ssl/cert.pem", srv.Params["ssl_certificate"])
	assert.Equal(t, "/etc/ssl/key.pem", srv.Params["ssl_certificate_key"])

	require.Len(t, srv.Locations, 2)
	assert.Equal(t, "/", srv.Locations[0].Path)
	assert.Equal(t, "http://backend", srv.Locations[0].ProxyPass)
	assert.Equal(t, "/static", srv.Locations[1].Path)
	assert.Equal(t, "/var/www/static", srv.Locations[1].Root)
	assert.Equal(t, "30d", srv.Locations[1].Params["expires"])
}

func TestParseNginxServerBlockSSLViaListen(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "listen", Args: []string{"443", "ssl"}},
		{Name: "server_name", Args: []string{"secure.example.com"}},
	}

	srv := parseNginxServerBlock(directives)
	assert.True(t, srv.SSL)
}

func TestParseNginxServerBlockNoSSL(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "listen", Args: []string{"80"}},
		{Name: "server_name", Args: []string{"plain.example.com"}},
	}

	srv := parseNginxServerBlock(directives)
	assert.False(t, srv.SSL)
}

func TestParseNginxUpstreamBlock(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "least_conn"},
		{Name: "server", Args: []string{"127.0.0.1:8080"}},
		{Name: "server", Args: []string{"127.0.0.1:8081", "weight=3"}},
		{Name: "keepalive", Args: []string{"32"}},
	}

	up := parseNginxUpstreamBlock("backend", directives)
	assert.Equal(t, "backend", up.Name)
	require.Len(t, up.Servers, 2)
	assert.Equal(t, "127.0.0.1:8080", up.Servers[0])
	assert.Equal(t, "127.0.0.1:8081 weight=3", up.Servers[1])
	assert.Equal(t, "32", up.Params["keepalive"])
	assert.Equal(t, "", up.Params["least_conn"])
}

func TestParseNginxLocationBlock(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "proxy_pass", Args: []string{"http://backend"}},
		{Name: "proxy_set_header", Args: []string{"Host", "$host"}},
		{Name: "proxy_set_header", Args: []string{"X-Real-IP", "$remote_addr"}},
		{Name: "root", Args: []string{"/var/www"}},
	}

	loc := parseNginxLocationBlock("/api", directives)
	assert.Equal(t, "/api", loc.Path)
	assert.Equal(t, "http://backend", loc.ProxyPass)
	assert.Equal(t, "/var/www", loc.Root)
	assert.Equal(t, "Host $host,X-Real-IP $remote_addr", loc.Params["proxy_set_header"])
}

func TestWalkHTTPBlock(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "server_tokens", Args: []string{"off"}},
		{Name: "sendfile", Args: []string{"on"}},
		{Name: "upstream", Args: []string{"backend"}, Block: []nginx.Directive{
			{Name: "server", Args: []string{"127.0.0.1:8080"}},
			{Name: "server", Args: []string{"127.0.0.1:8081"}},
		}},
		{Name: "server", Block: []nginx.Directive{
			{Name: "listen", Args: []string{"80"}},
			{Name: "server_name", Args: []string{"example.com"}},
			{Name: "location", Args: []string{"/"}, Block: []nginx.Directive{
				{Name: "proxy_pass", Args: []string{"http://backend"}},
			}},
		}},
		{Name: "server", Block: []nginx.Directive{
			{Name: "listen", Args: []string{"443", "ssl"}},
			{Name: "server_name", Args: []string{"example.com"}},
		}},
	}

	httpParams := map[string]any{}
	var servers []nginxServer
	var upstreams []nginxUpstream
	var listenAddrs []string

	walkHTTPBlock(directives, httpParams, &servers, &upstreams, &listenAddrs)

	// HTTP params
	assert.Equal(t, "off", httpParams["server_tokens"])
	assert.Equal(t, "on", httpParams["sendfile"])

	// Upstreams
	require.Len(t, upstreams, 1)
	assert.Equal(t, "backend", upstreams[0].Name)
	require.Len(t, upstreams[0].Servers, 2)

	// Servers
	require.Len(t, servers, 2)
	assert.Equal(t, "example.com", servers[0].ServerName)
	assert.Equal(t, "80", servers[0].Listen)
	assert.False(t, servers[0].SSL)
	require.Len(t, servers[0].Locations, 1)
	assert.Equal(t, "example.com", servers[1].ServerName)
	assert.Equal(t, "443 ssl", servers[1].Listen)
	assert.True(t, servers[1].SSL)

	// Listen addresses
	require.Len(t, listenAddrs, 2)
	assert.Equal(t, "80", listenAddrs[0])
	assert.Equal(t, "443 ssl", listenAddrs[1])
}

func TestWalkStreamBlock(t *testing.T) {
	// Parse real config text rather than hand-built directives so the test
	// also covers the tokenizer dropping the trailing comment.
	directives, err := nginx.Parse(`
stream {
    log_format basic '$remote_addr $protocol';
    upstream postgres {
        least_conn;
        server 10.0.0.1:5432 weight=2;
        server 10.0.0.2:5432 backup;
    }
    server {
        listen 5432 ssl;
        ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3 (POODLE), TLS 1.0, 1.1
        ssl_certificate /etc/ssl/db.pem;
        proxy_pass postgres;
    }
    server {
        listen 53 udp;
        proxy_pass dns_backend;
    }
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	require.Equal(t, "stream", directives[0].Name)

	streamParams := map[string]any{}
	var servers []nginxServer
	var upstreams []nginxUpstream
	walkStreamBlock(directives[0].Block, streamParams, &servers, &upstreams)

	assert.Equal(t, "basic $remote_addr $protocol", streamParams["log_format"])

	require.Len(t, upstreams, 1)
	assert.Equal(t, "postgres", upstreams[0].Name)
	assert.Equal(t, "least_conn", upstreams[0].LoadBalancingMethod)
	require.Len(t, upstreams[0].ServerDetails, 2)
	assert.Equal(t, int64(2), upstreams[0].ServerDetails[0].Weight)
	assert.True(t, upstreams[0].ServerDetails[1].Backup)

	require.Len(t, servers, 2)

	// The TLS listener: the trailing comment must not reach the value.
	assert.True(t, servers[0].SSL)
	assert.Equal(t, "TLSv1.2 TLSv1.3", servers[0].SSLProtocols)
	assert.Equal(t, "/etc/ssl/db.pem", servers[0].SSLCertificate)
	assert.Equal(t, "postgres", servers[0].Params["proxy_pass"])
	require.Len(t, servers[0].Listens, 1)
	assert.Equal(t, int64(5432), servers[0].Listens[0].Port)
	assert.False(t, servers[0].Listens[0].UDP)

	// The UDP listener.
	require.Len(t, servers[1].Listens, 1)
	assert.Equal(t, int64(53), servers[1].Listens[0].Port)
	assert.True(t, servers[1].Listens[0].UDP)
	assert.False(t, servers[1].SSL)

	// Directives that only exist in an http server block stay unset.
	assert.Empty(t, servers[1].ServerName)
	assert.Empty(t, servers[1].Locations)
}

func TestSetNginxParam(t *testing.T) {
	t.Run("simple param overwrites", func(t *testing.T) {
		m := map[string]any{}
		setNginxParam(m, "worker_processes", "auto")
		assert.Equal(t, "auto", m["worker_processes"])

		setNginxParam(m, "worker_processes", "4")
		assert.Equal(t, "4", m["worker_processes"])
	})

	t.Run("multi-param concatenates", func(t *testing.T) {
		m := map[string]any{}
		setNginxParam(m, "add_header", "X-Frame-Options DENY")
		setNginxParam(m, "add_header", "X-Content-Type-Options nosniff")
		assert.Equal(t, "X-Frame-Options DENY,X-Content-Type-Options nosniff", m["add_header"])
	})

	t.Run("listen multi-param", func(t *testing.T) {
		m := map[string]any{}
		setNginxParam(m, "listen", "80")
		setNginxParam(m, "listen", "443 ssl")
		assert.Equal(t, "80,443 ssl", m["listen"])
	})
}

func TestNginxConfPathDefault(t *testing.T) {
	assert.Equal(t, "/etc/nginx/nginx.conf", defaultNginxConf)
}

func TestScanBinaryForTagNginx(t *testing.T) {
	tag := []byte("nginx/")

	writeBinary := func(t *testing.T, data []byte) *afero.Afero {
		t.Helper()
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/usr/sbin/nginx", data, 0o755))
		return &afero.Afero{Fs: fs}
	}

	t.Run("embedded version in binary data", func(t *testing.T) {
		afs := writeBinary(t, []byte("\x00\x00nginx/1.25.3\x00\x00"))
		assert.Equal(t, "1.25.3", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})

	t.Run("four-part version", func(t *testing.T) {
		afs := writeBinary(t, []byte("some binary stuff\x00nginx/1.21.4.2\x00more stuff"))
		assert.Equal(t, "1.21.4.2", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})

	t.Run("no version tag", func(t *testing.T) {
		afs := writeBinary(t, []byte("no version here"))
		assert.Equal(t, "", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})

	t.Run("file does not exist", func(t *testing.T) {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		assert.Equal(t, "", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})

	t.Run("tag without version digits", func(t *testing.T) {
		afs := writeBinary(t, []byte("nginx/\x00rest"))
		assert.Equal(t, "", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})

	t.Run("version spanning chunk boundary", func(t *testing.T) {
		// Build data where "nginx/1.25.3" straddles a 64KB boundary.
		prefix := make([]byte, 64*1024-3)
		data := append(prefix, []byte("nginx/1.25.3\x00")...)
		afs := writeBinary(t, data)
		assert.Equal(t, "1.25.3", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})

	t.Run("version literal at exact chunkSize+overlap boundary", func(t *testing.T) {
		// Position the version so its numeric run reaches exactly the end of
		// the first full buffer read (chunkSize+overlap) while more file data
		// remains. The trailing digit ("2") lands in the next chunk. Without
		// the fix the scanner returns a truncated "1.25.6" instead of the
		// full "1.25.62".
		const chunkSize = 64 * 1024
		overlap := len(tag) + 20
		bufLen := chunkSize + overlap
		head := append([]byte("nginx/"), []byte("1.25.6")...) // ends at bufLen
		prefix := make([]byte, bufLen-len(head))
		data := append(prefix, head...)
		data = append(data, []byte("2\x00trailing")...)
		afs := writeBinary(t, data)
		assert.Equal(t, "1.25.62", scanBinaryForTag(afs, "/usr/sbin/nginx", tag))
	})
}

// chunkReader returns at most max bytes per Read, letting tests exercise the
// short-read paths of scanReaderForTag (a tag or version literal split across
// multiple Reads).
type chunkReader struct {
	data []byte
	pos  int
	max  int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := len(c.data) - c.pos
	if n > c.max {
		n = c.max
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

func TestScanReaderForTagShortReads(t *testing.T) {
	tag := []byte("nginx/")
	overlap := len(tag) + 20

	t.Run("tag split across two short reads", func(t *testing.T) {
		// Three bytes per Read forces the "nginx/" tag itself to span
		// several reads. The pre-fix short-read handling discarded the
		// unmatched tail (carry = 0), missing the tag entirely.
		data := []byte("\x00\x00nginx/1.25.3\x00")
		r := &chunkReader{data: data, max: 3}
		assert.Equal(t, "1.25.3", scanReaderForTag(r, tag, overlap, isApacheVersionByte))
	})

	t.Run("version literal split across short reads", func(t *testing.T) {
		// Small reads make the numeric run reach the buffer end mid-version
		// while more data remains. The pre-fix return-on-boundary truncated
		// this to "1.25.6".
		data := []byte("nginx/1.25.62\x00")
		r := &chunkReader{data: data, max: 4}
		assert.Equal(t, "1.25.62", scanReaderForTag(r, tag, overlap, isApacheVersionByte))
	})

	t.Run("version ends exactly at final EOF read", func(t *testing.T) {
		// The version literal runs to the very end of the data with no
		// trailing terminator, so the final bytes arrive on the read that
		// also reports io.EOF.
		data := []byte("nginx/1.25.62")
		r := &chunkReader{data: data, max: 4}
		assert.Equal(t, "1.25.62", scanReaderForTag(r, tag, overlap, isApacheVersionByte))
	})
}

func TestNginxVersionRegex(t *testing.T) {
	t.Run("standard command output", func(t *testing.T) {
		output := []byte("nginx version: nginx/1.25.3\n")
		m := reNginxVersion.FindSubmatch(output)
		require.NotNil(t, m)
		assert.Equal(t, "1.25.3", string(m[1]))
	})

	t.Run("openresty variant", func(t *testing.T) {
		m := reNginxVersion.FindSubmatch([]byte("nginx version: nginx/1.21.4.2\n"))
		require.NotNil(t, m)
		assert.Equal(t, "1.21.4.2", string(m[1]))
	})
}

func TestParseNginxModules(t *testing.T) {
	output := "nginx version: nginx/1.25.3\n" +
		"built by gcc 12.2.0 (Debian 12.2.0-14)\n" +
		"built with OpenSSL 3.0.11 19 Sep 2023\n" +
		"TLS SNI support enabled\n" +
		"configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx " +
		"--with-compat --with-threads " +
		"--with-http_ssl_module --with-http_v2_module " +
		"--with-http_gzip_static_module --with-stream_ssl_module " +
		"--with-mail_ssl_module\n"

	modules := parseNginxModules(output)
	require.Len(t, modules, 5)
	assert.Equal(t, "http_ssl_module", modules[0])
	assert.Equal(t, "http_v2_module", modules[1])
	assert.Equal(t, "http_gzip_static_module", modules[2])
	assert.Equal(t, "stream_ssl_module", modules[3])
	assert.Equal(t, "mail_ssl_module", modules[4])
}

func TestParseNginxModulesEmpty(t *testing.T) {
	output := "nginx version: nginx/1.25.3\nconfigure arguments: --prefix=/etc/nginx\n"
	modules := parseNginxModules(output)
	assert.Empty(t, modules)
}

// New tests for TLS, header collection, listen parsing, upstream details, and
// location modifier handling.

func TestParseNginxServerBlockTLSAndHeaders(t *testing.T) {
	directives := []nginx.Directive{
		{Name: "listen", Args: []string{"443", "ssl", "http2", "default_server"}},
		{Name: "server_name", Args: []string{"secure.example.com"}},
		{Name: "ssl_certificate", Args: []string{"/etc/ssl/cert.pem"}},
		{Name: "ssl_certificate_key", Args: []string{"/etc/ssl/key.pem"}},
		{Name: "ssl_protocols", Args: []string{"TLSv1.2", "TLSv1.3"}},
		{Name: "ssl_ciphers", Args: []string{"HIGH:!aNULL:!MD5"}},
		{Name: "ssl_prefer_server_ciphers", Args: []string{"on"}},
		{Name: "ssl_session_tickets", Args: []string{"off"}},
		{Name: "ssl_session_timeout", Args: []string{"1d"}},
		{Name: "server_tokens", Args: []string{"off"}},
		{Name: "add_header", Args: []string{"X-Frame-Options", "DENY", "always"}},
		{Name: "add_header", Args: []string{"Strict-Transport-Security", "max-age=63072000"}},
		{Name: "add_header", Args: []string{"X-Frame-Options", "SAMEORIGIN"}},
	}

	srv := parseNginxServerBlock(directives)

	assert.True(t, srv.SSL, "listen flag `ssl` must mark the server as SSL")
	assert.Equal(t, "/etc/ssl/cert.pem", srv.SSLCertificate)
	assert.Equal(t, "/etc/ssl/key.pem", srv.SSLCertificateKey)
	assert.Equal(t, "TLSv1.2 TLSv1.3", srv.SSLProtocols)
	assert.Equal(t, "HIGH:!aNULL:!MD5", srv.SSLCiphers)
	assert.True(t, srv.SSLPreferServerCiphers, "ssl_prefer_server_ciphers `on` must be true")
	assert.Equal(t, "off", srv.SSLSessionTickets)
	assert.Equal(t, "1d", srv.SSLSessionTimeout)
	assert.Equal(t, "off", srv.ServerTokens)

	// Headers must accumulate by name in order.
	require.Len(t, srv.Listens, 1)
	l := srv.Listens[0]
	assert.True(t, l.SSL)
	assert.True(t, l.HTTP2)
	assert.True(t, l.DefaultServer)
	assert.False(t, l.ProxyProtocol)
	assert.Equal(t, int64(443), l.Port)

	assert.Equal(t,
		[]string{"DENY always", "SAMEORIGIN"},
		srv.AddHeaders["X-Frame-Options"],
		"add_header collects every value per name in source order, including trailing flags")
	assert.Equal(t,
		[]string{"max-age=63072000"},
		srv.AddHeaders["Strict-Transport-Security"])
}

func TestParseNginxListen(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want nginxListen
	}{
		{"bare port", []string{"80"}, nginxListen{Raw: "80", Port: 80}},
		{"port + ssl", []string{"443", "ssl"}, nginxListen{Raw: "443 ssl", Port: 443, SSL: true}},
		{"ipv4 host:port", []string{"127.0.0.1:8080"}, nginxListen{Raw: "127.0.0.1:8080", Address: "127.0.0.1", Port: 8080}},
		{"ipv6 host:port", []string{"[::]:443", "ssl"}, nginxListen{Raw: "[::]:443 ssl", Address: "[::]", Port: 443, SSL: true}},
		{"default_server + http2", []string{"443", "ssl", "http2", "default_server"}, nginxListen{
			Raw: "443 ssl http2 default_server", Port: 443, SSL: true, HTTP2: true, DefaultServer: true,
		}},
		{"proxy_protocol", []string{"80", "proxy_protocol"}, nginxListen{
			Raw: "80 proxy_protocol", Port: 80, ProxyProtocol: true,
		}},
		{"unix socket", []string{"unix:/var/run/nginx.sock"}, nginxListen{
			Raw: "unix:/var/run/nginx.sock", Address: "unix:/var/run/nginx.sock",
		}},
		{"stream udp", []string{"53", "udp"}, nginxListen{Raw: "53 udp", Port: 53, UDP: true}},
		{"stream udp on an address", []string{"127.0.0.1:53", "udp", "reuseport"}, nginxListen{
			Raw: "127.0.0.1:53 udp reuseport", Address: "127.0.0.1", Port: 53, UDP: true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNginxListen(tc.args)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseNginxUpstreamBlockLoadBalancing(t *testing.T) {
	t.Run("default round_robin", func(t *testing.T) {
		up := parseNginxUpstreamBlock("backend", []nginx.Directive{
			{Name: "server", Args: []string{"127.0.0.1:8080"}},
		})
		assert.Equal(t, "round_robin", up.LoadBalancingMethod)
	})

	t.Run("least_conn", func(t *testing.T) {
		up := parseNginxUpstreamBlock("backend", []nginx.Directive{
			{Name: "least_conn"},
			{Name: "server", Args: []string{"127.0.0.1:8080"}},
		})
		assert.Equal(t, "least_conn", up.LoadBalancingMethod)
	})

	t.Run("ip_hash", func(t *testing.T) {
		up := parseNginxUpstreamBlock("backend", []nginx.Directive{
			{Name: "ip_hash"},
			{Name: "server", Args: []string{"127.0.0.1:8080"}},
		})
		assert.Equal(t, "ip_hash", up.LoadBalancingMethod)
	})

	t.Run("hash / random / least_time", func(t *testing.T) {
		for _, method := range []string{"hash", "random", "least_time"} {
			up := parseNginxUpstreamBlock("b", []nginx.Directive{{Name: method}})
			assert.Equal(t, method, up.LoadBalancingMethod, "method %q", method)
		}
	})

	t.Run("keepalive parsed numerically", func(t *testing.T) {
		up := parseNginxUpstreamBlock("backend", []nginx.Directive{
			{Name: "keepalive", Args: []string{"32"}},
		})
		assert.Equal(t, int64(32), up.Keepalive)
	})

	t.Run("keepalive not capped at TCP port range", func(t *testing.T) {
		// keepalive is a connection-count, not a TCP port — values above
		// 65535 must not be silently zeroed.
		up := parseNginxUpstreamBlock("backend", []nginx.Directive{
			{Name: "keepalive", Args: []string{"100000"}},
		})
		assert.Equal(t, int64(100000), up.Keepalive)
	})
}

func TestParseUpstreamServer(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want nginxUpstreamServer
	}{
		{"address only", []string{"127.0.0.1:8080"}, nginxUpstreamServer{Address: "127.0.0.1:8080"}},
		{"weight + max_fails + fail_timeout", []string{
			"backend1.example.com", "weight=3", "max_fails=2", "fail_timeout=30s",
		}, nginxUpstreamServer{Address: "backend1.example.com", Weight: 3, MaxFails: 2, FailTimeout: "30s"}},
		{"weight above TCP port cap is preserved", []string{
			"backend4", "weight=100000",
		}, nginxUpstreamServer{Address: "backend4", Weight: 100000}},
		{"backup + down", []string{"backend2", "backup", "down"}, nginxUpstreamServer{
			Address: "backend2", Backup: true, Down: true,
		}},
		{"slow_start + route", []string{"backend3", "slow_start=30s", "route=a"}, nginxUpstreamServer{
			Address: "backend3", SlowStart: "30s", Route: "a",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUpstreamServer(tc.args)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseNginxLocationModifiers(t *testing.T) {
	cases := []struct {
		name     string
		arg      string
		wantMod  string
		wantPath string
	}{
		{"prefix default", "/api", "", "/api"},
		{"exact", "= /api", "=", "/api"},
		{"case-sensitive regex", "~ ^/api/(.*)$", "~", "^/api/(.*)$"},
		{"case-insensitive regex", "~* \\.jpg$", "~*", `\.jpg$`},
		{"preferential prefix", "^~ /static/", "^~", "/static/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mod, p := splitLocationModifier(tc.arg)
			assert.Equal(t, tc.wantMod, mod)
			assert.Equal(t, tc.wantPath, p)
		})
	}
}

func TestParseNginxLocationDetail(t *testing.T) {
	loc := parseNginxLocationBlock("~ ^/api/(.*)$", []nginx.Directive{
		{Name: "try_files", Args: []string{"$uri", "$uri/", "=404"}},
		{Name: "return", Args: []string{"301", "https://example.com$request_uri"}},
		{Name: "fastcgi_pass", Args: []string{"unix:/var/run/php-fpm.sock"}},
	})
	assert.Equal(t, "~", loc.Modifier)
	assert.Equal(t, "^/api/(.*)$", loc.Path)
	assert.Equal(t, "$uri $uri/ =404", loc.TryFiles)
	assert.Equal(t, "301 https://example.com$request_uri", loc.Return)
	assert.Equal(t, "unix:/var/run/php-fpm.sock", loc.FastcgiPass)
}

// The `return` field cannot be read from inside an MQL block: the compiler
// treats a bare `return` identifier as a return statement, so
// `nginx.conf.servers { locations { return } }` compiles and silently reads
// nothing. returnDirective carries the same value under a name the parser
// does not claim, so it has to be populated wherever `return` is.
func TestNginxLocationReturnDirective(t *testing.T) {
	loc := parseNginxLocationBlock("/old", []nginx.Directive{
		{Name: "return", Args: []string{"301", "https://example.com$request_uri"}},
	})
	empty := parseNginxLocationBlock("/plain", []nginx.Directive{
		{Name: "root", Args: []string{"/var/www/html"}},
	})

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	res, err := nginxLocations2Resources([]nginxLocation{loc, empty}, runtime, "nginx.conf/etc/nginx/nginx.conf")
	require.NoError(t, err)
	require.Len(t, res, 2)

	redirect := res[0].(*mqlNginxConfLocation)
	assert.Equal(t, "301 https://example.com$request_uri", redirect.ReturnDirective.Data)
	assert.Equal(t, redirect.Return.Data, redirect.ReturnDirective.Data)

	// a location without a return directive reads as the empty string on both
	// fields, never as a stale value from the previous location
	plain := res[1].(*mqlNginxConfLocation)
	assert.Equal(t, "", plain.ReturnDirective.Data)
	assert.Equal(t, plain.Return.Data, plain.ReturnDirective.Data)
}
