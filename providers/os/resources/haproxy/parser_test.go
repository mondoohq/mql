// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package haproxy

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_BasicSections(t *testing.T) {
	src := `
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend www
    bind *:80
    bind *:443 ssl crt /etc/haproxy/cert.pem alpn h2,http/1.1
    default_backend app

backend app
    balance roundrobin
    option httpchk GET /health HTTP/1.1
    server srv1 10.0.0.1:80 check
    server srv2 10.0.0.2:443 check ssl verify required
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 4)

	assert.Equal(t, "global", cfg.Sections[0].Type)
	assert.Equal(t, "", cfg.Sections[0].Name)
	assert.Len(t, cfg.Sections[0].Directives, 2)

	assert.Equal(t, "defaults", cfg.Sections[1].Type)
	assert.Equal(t, "", cfg.Sections[1].Name)
	assert.Len(t, cfg.Sections[1].Directives, 4)

	assert.Equal(t, "frontend", cfg.Sections[2].Type)
	assert.Equal(t, "www", cfg.Sections[2].Name)
	assert.Len(t, cfg.Sections[2].Directives, 3)

	assert.Equal(t, "backend", cfg.Sections[3].Type)
	assert.Equal(t, "app", cfg.Sections[3].Name)
	assert.Len(t, cfg.Sections[3].Directives, 4)
}

func TestParse_CommentsAndBlankLines(t *testing.T) {
	src := `
# top comment
global  # trailing comment
    daemon # inline
    # blank-line comment
    maxconn 4096
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)
	require.Len(t, cfg.Sections[0].Directives, 2)
	assert.Equal(t, "daemon", cfg.Sections[0].Directives[0].Name)
	assert.Equal(t, "maxconn", cfg.Sections[0].Directives[1].Name)
	assert.Equal(t, []string{"4096"}, cfg.Sections[0].Directives[1].Args)
}

func TestParse_QuotedArgs(t *testing.T) {
	src := `
frontend www
    bind *:80
    acl is_admin path_beg "/admin path"
    acl is_x hdr(host) -i 'example.com'
    http-request set-header X-Foo "bar baz"
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)

	d := cfg.Sections[0].Directives
	require.Len(t, d, 4)
	assert.Equal(t, []string{"is_admin", "path_beg", "/admin path"}, d[1].Args)
	assert.Equal(t, []string{"is_x", "hdr(host)", "-i", "example.com"}, d[2].Args)
	assert.Equal(t, []string{"set-header", "X-Foo", "bar baz"}, d[3].Args)
}

func TestParse_LineContinuation(t *testing.T) {
	src := `
frontend www
    http-request set-header X-Long \
        "value-part-1 value-part-2" \
        if some_acl
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)
	require.Len(t, cfg.Sections[0].Directives, 1)

	d := cfg.Sections[0].Directives[0]
	assert.Equal(t, "http-request", d.Name)
	assert.Equal(t, []string{"set-header", "X-Long", "value-part-1 value-part-2", "if", "some_acl"}, d.Args)
}

func TestParse_NamedDefaultsAndFrom(t *testing.T) {
	src := `
defaults strict
    mode http
    option httplog

defaults relaxed from strict
    timeout connect 10s

frontend www from strict
    bind *:80

backend app from relaxed
    balance leastconn
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 4)

	assert.Equal(t, "defaults", cfg.Sections[0].Type)
	assert.Equal(t, "strict", cfg.Sections[0].Name)
	assert.Equal(t, "", cfg.Sections[0].Inherits)

	assert.Equal(t, "defaults", cfg.Sections[1].Type)
	assert.Equal(t, "relaxed", cfg.Sections[1].Name)
	assert.Equal(t, "strict", cfg.Sections[1].Inherits)

	assert.Equal(t, "frontend", cfg.Sections[2].Type)
	assert.Equal(t, "www", cfg.Sections[2].Name)
	assert.Equal(t, "strict", cfg.Sections[2].Inherits)

	assert.Equal(t, "backend", cfg.Sections[3].Type)
	assert.Equal(t, "app", cfg.Sections[3].Name)
	assert.Equal(t, "relaxed", cfg.Sections[3].Inherits)
}

func TestParse_Include(t *testing.T) {
	files := map[string]string{
		"/etc/haproxy/haproxy.cfg": `
global
    daemon

!include /etc/haproxy/conf.d/frontends.cfg
!includeglob /etc/haproxy/conf.d/backends/*.cfg
`,
		"/etc/haproxy/conf.d/frontends.cfg": `
frontend www
    bind *:80
    default_backend app
`,
		"/etc/haproxy/conf.d/backends/app.cfg": `
backend app
    server srv1 10.0.0.1:80 check
`,
		"/etc/haproxy/conf.d/backends/api.cfg": `
backend api
    server api1 10.0.0.2:8080 check ssl
`,
	}

	open := func(p string) (io.ReadCloser, error) {
		content, ok := files[p]
		if !ok {
			return nil, &fileNotFound{p}
		}
		return io.NopCloser(strings.NewReader(content)), nil
	}
	glob := func(pattern string) ([]string, error) {
		// Stub glob: only `*.cfg` directly inside a single dir is supported.
		const star = "/*.cfg"
		if !strings.HasSuffix(pattern, star) {
			return nil, nil
		}
		dir := strings.TrimSuffix(pattern, star)
		var out []string
		for p := range files {
			if strings.HasPrefix(p, dir+"/") && strings.HasSuffix(p, ".cfg") && !strings.Contains(p[len(dir)+1:], "/") {
				out = append(out, p)
			}
		}
		return out, nil
	}

	cfg, err := ParseFiles("/etc/haproxy/haproxy.cfg", open, glob)
	require.NoError(t, err, "errors: %v", cfg.Errors)

	// One global + 1 frontend + 2 backends (api, app); glob expansion is
	// not order-deterministic so just check the set.
	require.Len(t, cfg.Sections, 4)

	types := map[string]int{}
	names := map[string]bool{}
	for _, s := range cfg.Sections {
		types[s.Type]++
		if s.Name != "" {
			names[s.Name] = true
		}
	}
	assert.Equal(t, 1, types["global"])
	assert.Equal(t, 1, types["frontend"])
	assert.Equal(t, 2, types["backend"])
	assert.True(t, names["www"])
	assert.True(t, names["app"])
	assert.True(t, names["api"])

	assert.Contains(t, cfg.Files, "/etc/haproxy/haproxy.cfg")
	assert.Contains(t, cfg.Files, "/etc/haproxy/conf.d/frontends.cfg")
	assert.Contains(t, cfg.Files, "/etc/haproxy/conf.d/backends/app.cfg")
	assert.Contains(t, cfg.Files, "/etc/haproxy/conf.d/backends/api.cfg")
}

type fileNotFound struct{ p string }

func (e *fileNotFound) Error() string { return "no such file: " + e.p }

func TestParse_UnterminatedQuoteIsRecoverable(t *testing.T) {
	src := `
frontend www
    bind *:80
    acl bad path_beg "unterminated
    acl ok path_beg /good
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.Error(t, err)
	require.Len(t, cfg.Sections, 1)
	// We still expect to see at least the bind + the recovered acl below.
	names := make(map[string]int)
	for _, d := range cfg.Sections[0].Directives {
		names[d.Name]++
	}
	assert.Equal(t, 1, names["bind"])
}

func TestParseBindLines(t *testing.T) {
	cfg, err := Parse("test.cfg", strings.NewReader(`
frontend www
    bind *:80
    bind 192.0.2.1:443,*:8443 ssl crt /etc/ssl/site.pem alpn h2,http/1.1 verify required
    bind [::]:443 ssl crt /etc/ssl/site.pem ssl-min-ver TLSv1.2 no-tlsv11
    bind /run/haproxy/admin.sock mode 660 level admin
    bind *:80-89
`))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)

	binds := ParseBindLines(cfg.Sections[0].Directives)
	require.Len(t, binds, 6, "expected 6 bind entries (one extra from the comma-split *:8443)")

	// First bind: *:80
	assert.Equal(t, "*", binds[0].Address)
	assert.Equal(t, int64(80), binds[0].Port)
	assert.False(t, binds[0].SSL)

	// Second bind: 192.0.2.1:443 (split off from comma list)
	assert.Equal(t, "192.0.2.1", binds[1].Address)
	assert.Equal(t, int64(443), binds[1].Port)
	assert.True(t, binds[1].SSL)
	assert.Equal(t, "/etc/ssl/site.pem", binds[1].Crt)
	assert.Equal(t, "h2,http/1.1", binds[1].ALPN)
	assert.Equal(t, "required", binds[1].Verify)

	// Third bind: *:8443 — shares the params of the second
	assert.Equal(t, "*", binds[2].Address)
	assert.Equal(t, int64(8443), binds[2].Port)
	assert.True(t, binds[2].SSL)

	// Fourth bind: [::]:443
	assert.Equal(t, "[::]", binds[3].Address)
	assert.Equal(t, int64(443), binds[3].Port)
	assert.True(t, binds[3].NoTLSv11)
	assert.Equal(t, "TLSv1.2", binds[3].SSLMinVer)

	// Fifth bind: unix socket
	assert.Equal(t, "/run/haproxy/admin.sock", binds[4].Address)
	assert.Equal(t, int64(0), binds[4].Port)
	assert.Equal(t, "660", binds[4].Params["mode"])
	assert.Equal(t, "admin", binds[4].Params["level"])

	// Sixth bind: port range
	assert.Equal(t, "*", binds[5].Address)
	assert.Equal(t, int64(80), binds[5].PortRangeStart)
	assert.Equal(t, int64(89), binds[5].PortRangeEnd)
}

func TestParseServerLines(t *testing.T) {
	cfg, err := Parse("test.cfg", strings.NewReader(`
backend app
    default-server check inter 2s rise 2 fall 3
    server srv1 10.0.0.1:80 check
    server srv2 10.0.0.2:443 check ssl verify required ca-file /etc/ssl/ca.pem weight 50 backup
    server srv3 unix@/run/srv3.sock disabled
    server srv4 [2001:db8::1]:8080 check sni www.example.com
`))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)

	servers := ParseServerLines(cfg.Sections[0].Directives)
	require.Len(t, servers, 4)

	assert.Equal(t, "srv1", servers[0].Name)
	assert.Equal(t, "10.0.0.1", servers[0].Address)
	assert.Equal(t, int64(80), servers[0].Port)
	assert.True(t, servers[0].Check)
	assert.False(t, servers[0].SSL)

	assert.Equal(t, "srv2", servers[1].Name)
	assert.True(t, servers[1].SSL)
	assert.Equal(t, "required", servers[1].Verify)
	assert.Equal(t, "/etc/ssl/ca.pem", servers[1].CAFile)
	assert.Equal(t, int64(50), servers[1].Weight)
	assert.True(t, servers[1].WeightSet)
	assert.True(t, servers[1].Backup)

	assert.Equal(t, "unix@/run/srv3.sock", servers[2].Address)
	assert.True(t, servers[2].Disabled)

	assert.Equal(t, "[2001:db8::1]", servers[3].Address)
	assert.Equal(t, int64(8080), servers[3].Port)
	assert.Equal(t, "www.example.com", servers[3].SNI)

	ds := ParseDefaultServer(cfg.Sections[0].Directives)
	require.NotNil(t, ds)
	assert.True(t, ds.Check)
	assert.Equal(t, "2s", ds.Inter)
	assert.Equal(t, int64(2), ds.Rise)
	assert.Equal(t, int64(3), ds.Fall)
}

func TestParseHTTPCheck(t *testing.T) {
	cfg, err := Parse("test.cfg", strings.NewReader(`
backend app
    option httpchk GET /health HTTP/1.1\r\nHost:\ www
    http-check send meth GET uri /health hdr Host www.example.com
    http-check expect status 200
`))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)

	hc := ParseHTTPCheck(cfg.Sections[0].Directives)
	assert.Equal(t, "GET", hc.Method)
	assert.Equal(t, "/health", hc.URI)
	assert.Contains(t, hc.Version, "HTTP/1.1")
	require.Len(t, hc.Send, 1)
	require.Len(t, hc.Expect, 1)
	assert.Contains(t, hc.Send[0], "/health")
	assert.Contains(t, hc.Expect[0], "200")
}

func TestParse_NoOption(t *testing.T) {
	cfg, err := Parse("test.cfg", strings.NewReader(`
backend app
    option httpchk GET /health
    no option httpchk
    option http-server-close
    no option httpclose
    server srv1 10.0.0.1:80 check
`))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 1)

	en, dis := CollectOptions(cfg.Sections[0].Directives)
	assert.Contains(t, en, "httpchk GET /health")
	assert.Contains(t, en, "http-server-close")
	assert.Contains(t, dis, "httpchk")
	assert.Contains(t, dis, "httpclose")

	hc := ParseHTTPCheck(cfg.Sections[0].Directives)
	assert.True(t, hc.Disable, "no option httpchk should disable the check")
}

func TestParse_Timeouts(t *testing.T) {
	cfg, err := Parse("test.cfg", strings.NewReader(`
defaults
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 10s
`))
	require.NoError(t, err)
	tm := CollectTimeouts(cfg.Sections[0].Directives)
	assert.Equal(t, "5s", tm["connect"])
	assert.Equal(t, "30s", tm["client"])
	assert.Equal(t, "30s", tm["server"])
	assert.Equal(t, "10s", tm["http-request"])
}

func TestFindStickOn(t *testing.T) {
	cfg, err := Parse("test.cfg", strings.NewReader(`
backend app
    stick on src
    stick-table type ip size 100k

backend other
    stick on src table app/sessions if !condA

backend nostick
    stick-table type ip size 100k

backend match-only
    stick match req.cook(SID)
`))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 4)

	// `stick on src` → captured expr is "src", without the leading "on".
	assert.Equal(t, "src", FindStickOn(cfg.Sections[0].Directives))

	// Extra args after the expression (`table ... if ...`) are preserved.
	assert.Equal(t, "src table app/sessions if !condA",
		FindStickOn(cfg.Sections[1].Directives))

	// `stick-table` alone (no `stick on ...`) yields "".
	assert.Empty(t, FindStickOn(cfg.Sections[2].Directives))

	// `stick match ...` is not a `stick on` variant — should be ignored.
	assert.Empty(t, FindStickOn(cfg.Sections[3].Directives))
}

func TestParse_TextOutsideSectionIsError(t *testing.T) {
	src := `
this is bad
global
    daemon
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.Error(t, err)
	require.Len(t, cfg.Sections, 1)
	require.GreaterOrEqual(t, len(cfg.Errors), 1)
}

func TestParsePeerLines_ClassicPeerAndServer(t *testing.T) {
	// The classic `peer <name> <addr>:<port>` form is still accepted by
	// HAProxy 1.6 through 3.x; `server` lines are the 2.0+ form.
	src := `
peers classicpeers
	peer p1 127.0.0.1:10001
	peer p2 192.0.2.11:10001

peers modern
	bind 127.0.0.1:10002
	server local
	server remote 192.0.2.12:10002
`
	cfg, err := Parse("test.cfg", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Sections, 2)

	classic := ParsePeerLines(cfg.Sections[0].Directives)
	require.Len(t, classic, 2)
	assert.Equal(t, "p1", classic[0].Name)
	assert.Equal(t, "127.0.0.1", classic[0].Address)
	assert.Equal(t, int64(10001), classic[0].Port)
	assert.Equal(t, "p2", classic[1].Name)
	assert.Equal(t, "192.0.2.11", classic[1].Address)

	modern := ParsePeerLines(cfg.Sections[1].Directives)
	require.Len(t, modern, 2)
	assert.Equal(t, "local", modern[0].Name)
	assert.Equal(t, "", modern[0].Address)
	assert.Equal(t, "remote", modern[1].Name)
	assert.Equal(t, int64(10002), modern[1].Port)
}

// option httpchk defaults to OPTIONS / HTTP/1.0, and haproxy 2.2+'s
// http-check send overrides the method, URI and version it names.
func TestParseHTTPCheckDefaultsAndSend(t *testing.T) {
	parse := func(body string) HTTPCheck {
		cfg, err := Parse("test.cfg", strings.NewReader("backend app\n"+body))
		require.NoError(t, err)
		return ParseHTTPCheck(cfg.Sections[0].Directives)
	}
	for _, tt := range []struct {
		body             string
		method, uri, ver string
	}{
		{"    option httpchk\n", "OPTIONS", "/", "HTTP/1.0"},
		{"    option httpchk /health\n", "OPTIONS", "/health", "HTTP/1.0"},
		{"    option httpchk GET /health\n", "GET", "/health", "HTTP/1.0"},
		{"    option httpchk\n    http-check send meth GET uri /ping\n    http-check expect status 204\n", "GET", "/ping", "HTTP/1.0"},
		{"    option httpchk\n    http-check send meth HEAD uri /ready ver HTTP/1.1 hdr Host www.example.com\n", "HEAD", "/ready", "HTTP/1.1"},
		{"    option httpchk\n    http-check send uri-lf /%[env(P)] body-lf x\n", "OPTIONS", "/%[env(P)]", "HTTP/1.0"},
		{"    option httpchk POST /x HTTP/1.1\n    http-check send ver HTTP/2\n", "POST", "/x", "HTTP/2"},
	} {
		hc := parse(tt.body)
		assert.Equal(t, tt.method, hc.Method, tt.body)
		assert.Equal(t, tt.uri, hc.URI, tt.body)
		assert.Equal(t, tt.ver, hc.Version, tt.body)
	}

	// no HTTP check configured
	hc := parse("    server s1 10.0.0.1:80 check\n")
	assert.Equal(t, "", hc.Method)
	assert.Equal(t, "", hc.URI)
}
