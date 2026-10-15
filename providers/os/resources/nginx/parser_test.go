// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nginx

import (
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------
// Tokenizer tests
// ----------------------------------------------------------------------

func TestTokenizeSimple(t *testing.T) {
	toks, errs := tokenize("worker_processes 1;")
	require.Empty(t, errs)
	require.Len(t, toks, 3)
	assert.Equal(t, "worker_processes", toks[0].text)
	assert.False(t, toks[0].isQuoted)
	assert.Equal(t, "1", toks[1].text)
	assert.Equal(t, ";", toks[2].text)
}

func TestTokenizeBlock(t *testing.T) {
	toks, errs := tokenize("events { worker_connections 1024; }")
	require.Empty(t, errs)
	var got []string
	for _, t := range toks {
		got = append(got, t.text)
	}
	assert.Equal(t, []string{"events", "{", "worker_connections", "1024", ";", "}"}, got)
}

func TestTokenizeQuotedStrings(t *testing.T) {
	t.Run("double quoted with spaces", func(t *testing.T) {
		toks, errs := tokenize(`set $foo "hello world";`)
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, "hello world", toks[2].text)
		assert.True(t, toks[2].isQuoted)
	})

	t.Run("single quoted with spaces", func(t *testing.T) {
		toks, errs := tokenize(`log_format main '$remote_addr - $request';`)
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, "$remote_addr - $request", toks[2].text)
		assert.True(t, toks[2].isQuoted)
	})

	t.Run("escape quote inside quoted string", func(t *testing.T) {
		toks, errs := tokenize(`add_header X-Test "he said \"hi\"";`)
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, `he said "hi"`, toks[2].text)
	})

	t.Run("quoted string preserves semicolons", func(t *testing.T) {
		toks, errs := tokenize(`set $x "a;b;c";`)
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, "a;b;c", toks[2].text)
		assert.True(t, toks[2].isQuoted)
		assert.Equal(t, ";", toks[3].text)
	})

	t.Run("quoted string preserves braces", func(t *testing.T) {
		toks, errs := tokenize(`set $json "{\"key\":1}";`)
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, `{"key":1}`, toks[2].text)
	})

	t.Run("quoted string spans newlines", func(t *testing.T) {
		toks, errs := tokenize("log_format main 'a\nb';")
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, "a\nb", toks[2].text)
	})

	t.Run("unterminated quoted string is reported", func(t *testing.T) {
		_, errs := tokenize(`set $foo "unterminated`)
		require.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Msg, "unterminated")
	})
}

func TestTokenizeComments(t *testing.T) {
	t.Run("line comment", func(t *testing.T) {
		toks, errs := tokenize("# a comment\nworker_processes 1;")
		require.Empty(t, errs)
		require.Len(t, toks, 3)
		assert.Equal(t, "worker_processes", toks[0].text)
	})

	t.Run("trailing comment", func(t *testing.T) {
		toks, errs := tokenize("worker_processes 1; # trailing\n")
		require.Empty(t, errs)
		require.Len(t, toks, 3)
	})

	t.Run("comment inside quoted string is preserved", func(t *testing.T) {
		toks, errs := tokenize(`set $x "hello # not a comment";`)
		require.Empty(t, errs)
		require.Len(t, toks, 4)
		assert.Equal(t, "hello # not a comment", toks[2].text)
	})
}

func TestTokenizeLineTracking(t *testing.T) {
	// Ensure line numbers advance through comments, newlines, and
	// multi-line strings.
	input := "# first\nworker_processes 1;\n\nhttp {\n    server_tokens off;\n}"
	toks, errs := tokenize(input)
	require.Empty(t, errs)

	byText := func(name string) *token {
		for i := range toks {
			if toks[i].text == name {
				return &toks[i]
			}
		}
		return nil
	}

	assert.Equal(t, 2, byText("worker_processes").line)
	assert.Equal(t, 4, byText("http").line)
	assert.Equal(t, 5, byText("server_tokens").line)
}

func TestTokenizeBraceDelimiterNotMergedWithText(t *testing.T) {
	// "server_name{" without whitespace should still produce two tokens
	// because '{' is a delimiter.
	toks, errs := tokenize("server_name{}")
	require.Empty(t, errs)
	require.Len(t, toks, 3)
	assert.Equal(t, "server_name", toks[0].text)
	assert.Equal(t, "{", toks[1].text)
	assert.Equal(t, "}", toks[2].text)
}

// ----------------------------------------------------------------------
// Parse: top-level directive tree
// ----------------------------------------------------------------------

func TestParseSimpleDirective(t *testing.T) {
	directives, err := Parse("worker_processes auto;")
	require.NoError(t, err)
	require.Len(t, directives, 1)

	d := directives[0]
	assert.Equal(t, "worker_processes", d.Name)
	assert.Equal(t, []string{"auto"}, d.Args)
	assert.Nil(t, d.Block)
	assert.False(t, d.IsBlock())
}

func TestParseMultipleSimpleDirectives(t *testing.T) {
	input := `
user nginx;
worker_processes 4;
pid /run/nginx.pid;
`
	directives, err := Parse(input)
	require.NoError(t, err)
	require.Len(t, directives, 3)
	assert.Equal(t, "user", directives[0].Name)
	assert.Equal(t, []string{"nginx"}, directives[0].Args)
	assert.Equal(t, "worker_processes", directives[1].Name)
	assert.Equal(t, "pid", directives[2].Name)
}

func TestParseBlockDirective(t *testing.T) {
	directives, err := Parse(`
events {
    worker_connections 1024;
    use epoll;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	events := directives[0]
	assert.Equal(t, "events", events.Name)
	assert.True(t, events.IsBlock())
	require.Len(t, events.Block, 2)
	assert.Equal(t, "worker_connections", events.Block[0].Name)
	assert.Equal(t, []string{"1024"}, events.Block[0].Args)
	assert.Equal(t, "use", events.Block[1].Name)
	assert.Equal(t, []string{"epoll"}, events.Block[1].Args)
}

func TestParseEmptyBlock(t *testing.T) {
	directives, err := Parse("events {}")
	require.NoError(t, err)
	require.Len(t, directives, 1)
	assert.Equal(t, "events", directives[0].Name)
	assert.True(t, directives[0].IsBlock())
	assert.Empty(t, directives[0].Block)
}

func TestParseNestedBlocks(t *testing.T) {
	directives, err := Parse(`
http {
    server {
        listen 80;
        server_name example.com;
        location / {
            proxy_pass http://backend;
        }
    }
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	httpBlock := directives[0]
	require.True(t, httpBlock.IsBlock())
	require.Len(t, httpBlock.Block, 1)

	server := httpBlock.Block[0]
	assert.Equal(t, "server", server.Name)
	require.True(t, server.IsBlock())
	require.Len(t, server.Block, 3)

	loc := server.Block[2]
	assert.Equal(t, "location", loc.Name)
	assert.Equal(t, []string{"/"}, loc.Args)
	require.True(t, loc.IsBlock())
	require.Len(t, loc.Block, 1)
	assert.Equal(t, "proxy_pass", loc.Block[0].Name)
	assert.Equal(t, []string{"http://backend"}, loc.Block[0].Args)
}

func TestParseDirectiveWithMultipleArgs(t *testing.T) {
	directives, err := Parse("listen 443 ssl http2 default_server;")
	require.NoError(t, err)
	require.Len(t, directives, 1)
	assert.Equal(t, []string{"443", "ssl", "http2", "default_server"}, directives[0].Args)
}

func TestParseBlockWithArgs(t *testing.T) {
	directives, err := Parse(`
location /api/v1 {
    proxy_pass http://api_backend;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	loc := directives[0]
	assert.Equal(t, "location", loc.Name)
	assert.Equal(t, []string{"/api/v1"}, loc.Args)
	require.True(t, loc.IsBlock())
}

func TestParseQuotedArgs(t *testing.T) {
	directives, err := Parse(`log_format main '$remote_addr "$request"';`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	assert.Equal(t, []string{"main", `$remote_addr "$request"`}, directives[0].Args)
}

func TestParseIfBlockWithParens(t *testing.T) {
	// `if ($foo = bar) { ... }` — parens end up as separate args because
	// nginx treats them as plain characters (not grammar delimiters).
	directives, err := Parse(`
if ($request_method = POST) {
    return 405;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	ifBlock := directives[0]
	assert.Equal(t, "if", ifBlock.Name)
	// parens are not specially tokenized — they attach to adjacent text.
	assert.Equal(t, []string{"($request_method", "=", "POST)"}, ifBlock.Args)
	require.True(t, ifBlock.IsBlock())
}

func TestParseRewriteWithRegex(t *testing.T) {
	directives, err := Parse(`rewrite ^/(.*)$ /new/$1 permanent;`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	assert.Equal(t, "rewrite", directives[0].Name)
	assert.Equal(t, []string{"^/(.*)$", "/new/$1", "permanent"}, directives[0].Args)
}

func TestParseMapBlockWithRegexKeys(t *testing.T) {
	directives, err := Parse(`
map $http_user_agent $mobile {
    default       0;
    "~*iphone"    1;
    "~*android"   1;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	m := directives[0]
	assert.Equal(t, "map", m.Name)
	assert.Equal(t, []string{"$http_user_agent", "$mobile"}, m.Args)
	require.Len(t, m.Block, 3)
	// Inside a map{}, each entry is "<key> <value>;". The first token
	// (possibly quoted) becomes the directive name; remaining tokens are
	// args. That matches nginx's own grammar and makes regex keys like
	// "~*iphone" accessible as Name.
	assert.Equal(t, "default", m.Block[0].Name)
	assert.Equal(t, []string{"0"}, m.Block[0].Args)
	assert.Equal(t, "~*iphone", m.Block[1].Name)
	assert.Equal(t, []string{"1"}, m.Block[1].Args)
}

func TestParseComments(t *testing.T) {
	directives, err := Parse(`
# top-level comment
user nginx; # trailing comment
# another
http {
    # inside block
    server_tokens off;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 2)
	assert.Equal(t, "user", directives[0].Name)
	assert.Equal(t, "http", directives[1].Name)
	require.Len(t, directives[1].Block, 1)
	assert.Equal(t, "server_tokens", directives[1].Block[0].Name)
}

func TestParseLineNumbers(t *testing.T) {
	input := `# header
worker_processes 1;

events {
    worker_connections 1024;
}
`
	directives, err := Parse(input)
	require.NoError(t, err)
	require.Len(t, directives, 2)
	assert.Equal(t, 2, directives[0].Line)
	assert.Equal(t, 4, directives[1].Line)
	assert.Equal(t, 5, directives[1].Block[0].Line)
}

func TestParseEmpty(t *testing.T) {
	directives, err := Parse("")
	require.NoError(t, err)
	assert.Empty(t, directives)
}

func TestParseWhitespaceOnly(t *testing.T) {
	directives, err := Parse("   \n\n\t  \n")
	require.NoError(t, err)
	assert.Empty(t, directives)
}

func TestParseOnlyComments(t *testing.T) {
	directives, err := Parse("# one\n# two\n# three\n")
	require.NoError(t, err)
	assert.Empty(t, directives)
}

// ----------------------------------------------------------------------
// Parse: error / recovery cases
// ----------------------------------------------------------------------

func TestParseMissingSemicolon(t *testing.T) {
	// Missing ; just before '}' should produce an error but still extract
	// the directive.
	directives, err := Parse(`
server {
    listen 80
}
`)
	require.Error(t, err)
	require.Len(t, directives, 1)
	server := directives[0]
	require.Len(t, server.Block, 1)
	assert.Equal(t, "listen", server.Block[0].Name)
	assert.Contains(t, err.Error(), "missing ';'")
}

func TestParseUnclosedBlock(t *testing.T) {
	directives, err := Parse(`
http {
    server_tokens off;
`)
	require.Error(t, err)
	// We still get the http block with the directives we've read
	require.Len(t, directives, 1)
	assert.Equal(t, "http", directives[0].Name)
	assert.Contains(t, err.Error(), "unclosed block")
}

func TestParseStrayCloseBrace(t *testing.T) {
	directives, err := Parse(`
user nginx;
}
worker_processes 1;
`)
	require.Error(t, err)
	// We still get the surrounding directives.
	require.Len(t, directives, 2)
	assert.Equal(t, "user", directives[0].Name)
	assert.Equal(t, "worker_processes", directives[1].Name)
	assert.Contains(t, err.Error(), "unexpected '}'")
}

func TestParseStraySemicolon(t *testing.T) {
	// A bare ';' with no directive name is nonsense; we report it and
	// continue.
	directives, err := Parse(`
user nginx;
;
worker_processes 1;
`)
	require.Error(t, err)
	require.Len(t, directives, 2)
}

func TestParseUnterminatedQuotedStringDoesNotPanic(t *testing.T) {
	// Defensive test — we must not crash on a malformed input.
	_, err := Parse(`set $foo "never closed`)
	require.Error(t, err)
}

// ----------------------------------------------------------------------
// Parse: real-world-ish configs
// ----------------------------------------------------------------------

const realWorldNginxConf = `
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    keepalive_timeout  65;

    upstream backend {
        least_conn;
        server 10.0.0.1:8080 weight=3;
        server 10.0.0.2:8080;
        keepalive 32;
    }

    server {
        listen       80;
        server_name  example.com www.example.com;
        return 301   https://$host$request_uri;
    }

    server {
        listen       443 ssl http2;
        server_name  example.com;

        ssl_certificate      /etc/ssl/certs/example.com.pem;
        ssl_certificate_key  /etc/ssl/private/example.com.key;

        location / {
            proxy_pass         http://backend;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
        }

        location /static/ {
            root /var/www/static;
            expires 30d;
        }
    }
}
`

func TestParseRealWorldConfig(t *testing.T) {
	directives, err := Parse(realWorldNginxConf)
	require.NoError(t, err)

	names := make([]string, 0, len(directives))
	for _, d := range directives {
		names = append(names, d.Name)
	}
	assert.Equal(t, []string{"user", "worker_processes", "error_log", "pid", "events", "http"}, names)

	// Drill into http{}: include, default_type, log_format, access_log,
	// sendfile, keepalive_timeout, upstream, server, server.
	httpBlock := directives[5]
	require.True(t, httpBlock.IsBlock())
	require.Len(t, httpBlock.Block, 9)

	// log_format main with the continuation-style concatenated strings
	// (nginx just takes the two quoted args separately).
	logFormat := httpBlock.Block[2]
	assert.Equal(t, "log_format", logFormat.Name)
	require.Len(t, logFormat.Args, 4)
	assert.Equal(t, "main", logFormat.Args[0])

	upstream := httpBlock.Block[6]
	assert.Equal(t, "upstream", upstream.Name)
	assert.Equal(t, []string{"backend"}, upstream.Args)
	require.True(t, upstream.IsBlock())

	serverHTTPS := httpBlock.Block[8]
	assert.Equal(t, "server", serverHTTPS.Name)
	require.True(t, serverHTTPS.IsBlock())
	// listen, server_name, ssl_certificate, ssl_certificate_key,
	// location /, location /static/.
	require.Len(t, serverHTTPS.Block, 6)

	listen := serverHTTPS.Block[0]
	assert.Equal(t, []string{"443", "ssl", "http2"}, listen.Args)

	locRoot := serverHTTPS.Block[4]
	assert.Equal(t, "location", locRoot.Name)
	assert.Equal(t, []string{"/"}, locRoot.Args)
	require.True(t, locRoot.IsBlock())
	require.Len(t, locRoot.Block, 3)
	assert.Equal(t, "proxy_pass", locRoot.Block[0].Name)
}

// ----------------------------------------------------------------------
// ParseFiles: include expansion
// ----------------------------------------------------------------------

type memFS struct {
	files map[string]string
}

func (m *memFS) open(path string) (io.ReadCloser, error) {
	c, ok := m.files[path]
	if !ok {
		return nil, fmt.Errorf("no such file: %s", path)
	}
	return io.NopCloser(strings.NewReader(c)), nil
}

// A fixed glob that looks up patterns in an explicit map so tests are
// deterministic (avoids depending on filepath.Match semantics).
type memGlob map[string][]string

func (g memGlob) expand(pattern string) ([]string, error) {
	if paths, ok := g[pattern]; ok {
		return paths, nil
	}
	if strings.ContainsAny(pattern, "*?[") {
		return nil, nil
	}
	return []string{pattern}, nil
}

func TestParseFilesBasicInclude(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
worker_processes 1;
include /etc/nginx/conf.d/example.conf;
`,
		"/etc/nginx/conf.d/example.conf": `
server {
    listen 80;
    server_name example.com;
}
`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)
	require.Empty(t, cfg.Errors)

	// Top-level directives post-expansion: worker_processes, server
	require.Len(t, cfg.Directives, 2)
	assert.Equal(t, "worker_processes", cfg.Directives[0].Name)
	assert.Equal(t, "server", cfg.Directives[1].Name)

	// Files visited: root + include
	assert.Equal(t, []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/example.conf",
	}, cfg.Files)
}

func TestParseFilesGlobInclude(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
http {
    include /etc/nginx/conf.d/*.conf;
}
`,
		"/etc/nginx/conf.d/site-a.conf": `server { listen 8080; server_name a.example.com; }`,
		"/etc/nginx/conf.d/site-b.conf": `server { listen 8081; server_name b.example.com; }`,
	}}
	glob := memGlob{
		"/etc/nginx/conf.d/*.conf": {
			"/etc/nginx/conf.d/site-a.conf",
			"/etc/nginx/conf.d/site-b.conf",
		},
	}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, glob.expand)
	require.NoError(t, err)
	require.Empty(t, cfg.Errors)

	require.Len(t, cfg.Directives, 1)
	http := cfg.Directives[0]
	require.True(t, http.IsBlock())
	require.Len(t, http.Block, 2, "both included server{} blocks should appear inside http{}")
	assert.Equal(t, "server", http.Block[0].Name)
	assert.Equal(t, []string{"8080"}, http.Block[0].Block[0].Args)
	assert.Equal(t, []string{"8081"}, http.Block[1].Block[0].Args)

	// All three files should be recorded.
	assert.ElementsMatch(t, []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/site-a.conf",
		"/etc/nginx/conf.d/site-b.conf",
	}, cfg.Files)
}

func TestParseFilesRelativeInclude(t *testing.T) {
	// include paths without a leading '/' are resolved against the root
	// file's directory (nginx's "prefix" behavior).
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `include mime.types;`,
		"/etc/nginx/mime.types": `types { text/html html; }`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)
	require.Empty(t, cfg.Errors)

	require.Len(t, cfg.Directives, 1)
	assert.Equal(t, "types", cfg.Directives[0].Name)
}

func TestParseFilesMissingIncludeIsNonFatal(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
worker_processes 1;
include /does/not/exist.conf;
server_tokens off;
`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err, "missing includes should not abort parsing")
	require.NotEmpty(t, cfg.Errors, "missing include should be recorded as an error")

	// The surrounding directives are still parsed.
	require.Len(t, cfg.Directives, 2)
	assert.Equal(t, "worker_processes", cfg.Directives[0].Name)
	assert.Equal(t, "server_tokens", cfg.Directives[1].Name)
}

func TestParseFilesMissingRootIsFatal(t *testing.T) {
	fs := &memFS{files: map[string]string{}}
	_, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.Error(t, err)
}

func TestParseFilesCycleDetection(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `include /etc/nginx/a.conf;`,
		"/etc/nginx/a.conf":     `include /etc/nginx/b.conf;`,
		"/etc/nginx/b.conf":     `include /etc/nginx/a.conf;`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err, "cyclical includes must not hang")
	// a.conf and b.conf are visited once each; the second include of
	// a.conf is dropped silently.
	assert.ElementsMatch(t, []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/a.conf",
		"/etc/nginx/b.conf",
	}, cfg.Files)
}

func TestParseFilesNestedIncludesPreserveOrder(t *testing.T) {
	// An include inside a block should inline the child's top-level
	// directives into that block, preserving document order.
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
http {
    server_tokens off;
    include /etc/nginx/common.conf;
    sendfile on;
}
`,
		"/etc/nginx/common.conf": `
keepalive_timeout 60;
server_names_hash_bucket_size 64;
`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)
	require.Empty(t, cfg.Errors)

	require.Len(t, cfg.Directives, 1)
	httpBlock := cfg.Directives[0]
	require.True(t, httpBlock.IsBlock())

	var names []string
	for _, d := range httpBlock.Block {
		names = append(names, d.Name)
	}
	assert.Equal(t, []string{
		"server_tokens",
		"keepalive_timeout",
		"server_names_hash_bucket_size",
		"sendfile",
	}, names)
}

func TestParseFilesNoOpenFunc(t *testing.T) {
	_, err := ParseFiles("/nginx.conf", nil, nil)
	require.Error(t, err)
}

func TestParseFilesIncludeWithBadGlob(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `include /etc/nginx/conf.d/*.conf;`,
	}}
	badGlob := func(pattern string) ([]string, error) {
		return nil, fmt.Errorf("boom")
	}
	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, badGlob)
	require.NoError(t, err)
	require.Len(t, cfg.Errors, 1)
	assert.Contains(t, cfg.Errors[0].Msg, "glob")
}

func TestParseErrorFormatting(t *testing.T) {
	e := ParseError{File: "/etc/nginx/nginx.conf", Line: 42, Msg: "whatever"}
	assert.Equal(t, "/etc/nginx/nginx.conf:42: whatever", e.Error())

	eNoFile := ParseError{Line: 5, Msg: "nope"}
	assert.Equal(t, "line 5: nope", eNoFile.Error())
}

// ----------------------------------------------------------------------
// Additional real-world parsing coverage
// ----------------------------------------------------------------------

func TestParseLocationWithRegexModifiers(t *testing.T) {
	cases := []struct {
		name  string
		input string
		args  []string
	}{
		{"exact match", `location = /exact { return 200; }`, []string{"=", "/exact"}},
		{"case-sensitive regex", `location ~ ^/api/ { return 200; }`, []string{"~", "^/api/"}},
		{"case-insensitive regex", `location ~* ^/Api/ { return 200; }`, []string{"~*", "^/Api/"}},
		{"prefix match", `location ^~ /static/ { return 200; }`, []string{"^~", "/static/"}},
		// The backslash in "\.php$" must survive tokenization — it is
		// a regex escape, not a config escape.
		{"regex with escaped dot", `location ~ \.php$ { deny all; }`, []string{"~", `\.php$`}},
		// Regex with alternation.
		{"regex with alternation", `location ~* \.(gif|jpg|png)$ { expires 30d; }`, []string{"~*", `\.(gif|jpg|png)$`}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			directives, err := Parse(tc.input)
			require.NoError(t, err)
			require.Len(t, directives, 1)
			assert.Equal(t, "location", directives[0].Name)
			assert.Equal(t, tc.args, directives[0].Args)
			assert.True(t, directives[0].IsBlock())
		})
	}
}

func TestParseBackslashEscapesInUnquotedText(t *testing.T) {
	// In unquoted text, `\` followed by a delimiter character IS consumed
	// as an escape. Any other `\X` sequence is preserved literally — this
	// is what makes regexes like `\.php` round-trip.
	t.Run("escaped semicolon survives as literal ;", func(t *testing.T) {
		directives, err := Parse(`weird a\;b;`)
		require.NoError(t, err)
		require.Len(t, directives, 1)
		assert.Equal(t, []string{"a;b"}, directives[0].Args)
	})

	t.Run("escaped brace survives as literal {", func(t *testing.T) {
		directives, err := Parse(`weird a\{b;`)
		require.NoError(t, err)
		require.Len(t, directives, 1)
		assert.Equal(t, []string{"a{b"}, directives[0].Args)
	})

	t.Run("backslash in regex preserved", func(t *testing.T) {
		directives, err := Parse(`weird \d+\.\d+;`)
		require.NoError(t, err)
		require.Len(t, directives, 1)
		assert.Equal(t, []string{`\d+\.\d+`}, directives[0].Args)
	})

	t.Run("backslash at end of line preserved", func(t *testing.T) {
		directives, err := Parse(`weird foo\bar;`)
		require.NoError(t, err)
		require.Len(t, directives, 1)
		assert.Equal(t, []string{`foo\bar`}, directives[0].Args)
	})
}

func TestParseMultiLineDirective(t *testing.T) {
	// Nginx lets a directive span multiple lines — there is no
	// continuation character; any whitespace (including '\n') is a
	// separator between args. We concatenate the three quoted args into
	// the directive's Args slice verbatim.
	directives, err := Parse(`
log_format main '$remote_addr - $remote_user '
                '[$time_local] "$request" '
                '$status $body_bytes_sent';
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	d := directives[0]
	assert.Equal(t, "log_format", d.Name)
	require.Len(t, d.Args, 4)
	assert.Equal(t, "main", d.Args[0])
	assert.Equal(t, "$remote_addr - $remote_user ", d.Args[1])
	assert.Equal(t, `[$time_local] "$request" `, d.Args[2])
	assert.Equal(t, "$status $body_bytes_sent", d.Args[3])
}

func TestParseIfWithRegexOperators(t *testing.T) {
	// '~' is a regex-match operator; '!~' is negated case-sensitive.
	// Both must survive tokenization as distinct args when space-separated.
	directives, err := Parse(`
if ($http_user_agent ~ "MSIE") {
    return 403;
}

if ($http_x_forwarded_proto !~* "^https$") {
    return 301 https://$host$request_uri;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 2)

	assert.Equal(t, "if", directives[0].Name)
	assert.Equal(t, []string{"($http_user_agent", "~", "MSIE", ")"}, directives[0].Args)

	assert.Equal(t, "if", directives[1].Name)
	assert.Equal(t, []string{"($http_x_forwarded_proto", "!~*", "^https$", ")"}, directives[1].Args)
}

func TestParseDirectiveWithNoArgs(t *testing.T) {
	// "internal;" / "access_log off;" / "deny all;" — but also some
	// directives take no args at all, e.g. "aio_write;" or the
	// "listen ... default_server reuseport;" family. The bare form just
	// means Args is empty.
	directives, err := Parse(`internal;`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	assert.Equal(t, "internal", directives[0].Name)
	assert.Empty(t, directives[0].Args)
}

func TestParseTypesBlock(t *testing.T) {
	// The types block maps MIME types to extensions. Each entry is
	// `<mime/type> <ext> <ext> ...;`.
	directives, err := Parse(`
types {
    text/html html htm shtml;
    text/css  css;
    image/jpeg jpg jpeg;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	types := directives[0]
	require.True(t, types.IsBlock())
	require.Len(t, types.Block, 3)
	assert.Equal(t, "text/html", types.Block[0].Name)
	assert.Equal(t, []string{"html", "htm", "shtml"}, types.Block[0].Args)
	assert.Equal(t, "text/css", types.Block[1].Name)
	assert.Equal(t, "image/jpeg", types.Block[2].Name)
}

func TestParseGeoBlock(t *testing.T) {
	// geo{} blocks map IP ranges to values with key/value lines.
	directives, err := Parse(`
geo $clientRealIp $is_internal {
    default         0;
    10.0.0.0/8      1;
    192.168.0.0/16  1;
    172.16.0.0/12   1;
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	geo := directives[0]
	assert.Equal(t, "geo", geo.Name)
	assert.Equal(t, []string{"$clientRealIp", "$is_internal"}, geo.Args)
	require.True(t, geo.IsBlock())
	require.Len(t, geo.Block, 4)
	assert.Equal(t, "10.0.0.0/8", geo.Block[1].Name)
	assert.Equal(t, []string{"1"}, geo.Block[1].Args)
}

func TestParseDirectiveValueWithVariablesAndBracesInsideQuotes(t *testing.T) {
	// `${var}` substitution should survive tokenization when inside
	// quotes — the brace is a delimiter only outside of a quoted string.
	directives, err := Parse(`set $full "${scheme}://${host}${request_uri}";`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	d := directives[0]
	assert.Equal(t, []string{"$full", "${scheme}://${host}${request_uri}"}, d.Args)
}

func TestParseDeeplyNestedBlocks(t *testing.T) {
	// Defense against stack or off-by-one issues at depth.
	directives, err := Parse(`
http {
    server {
        location / {
            location /inner {
                location /deep {
                    return 200 "leaf";
                }
            }
        }
    }
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)

	// Drill in.
	cur := directives[0]
	wanted := []string{"http", "server", "location", "location", "location"}
	for i, name := range wanted {
		assert.Equal(t, name, cur.Name, "level %d", i)
		require.True(t, cur.IsBlock(), "level %d should be a block", i)
		if i < len(wanted)-1 {
			require.NotEmpty(t, cur.Block)
			cur = cur.Block[0]
		}
	}

	// Innermost `location /deep` contains `return 200 "leaf";`
	require.Len(t, cur.Block, 1)
	ret := cur.Block[0]
	assert.Equal(t, "return", ret.Name)
	assert.Equal(t, []string{"200", "leaf"}, ret.Args)
}

func TestParseSiblingsInSameBlock(t *testing.T) {
	// Multiple server{} blocks must NOT get swallowed into each other.
	directives, err := Parse(`
http {
    server { listen 80; server_name one.com; }
    server { listen 81; server_name two.com; }
    server { listen 82; server_name three.com; }
}
`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	httpBlock := directives[0]
	require.Len(t, httpBlock.Block, 3)

	for i, want := range []string{"one.com", "two.com", "three.com"} {
		srv := httpBlock.Block[i]
		require.True(t, srv.IsBlock())
		// server_name is the 2nd directive.
		require.Len(t, srv.Block, 2)
		assert.Equal(t, "server_name", srv.Block[1].Name)
		assert.Equal(t, []string{want}, srv.Block[1].Args)
	}
}

func TestParseDirectiveFollowingEmptyBlockSibling(t *testing.T) {
	// Catches regressions where `{}` consumes the following directive.
	directives, err := Parse(`events {} http { server_tokens off; }`)
	require.NoError(t, err)
	require.Len(t, directives, 2)
	assert.Equal(t, "events", directives[0].Name)
	assert.True(t, directives[0].IsBlock())
	assert.Empty(t, directives[0].Block)
	assert.Equal(t, "http", directives[1].Name)
	require.Len(t, directives[1].Block, 1)
}

func TestParseBlankValuesInQuotes(t *testing.T) {
	// An explicit empty string argument, e.g. `set $x "";`.
	directives, err := Parse(`set $x "";`)
	require.NoError(t, err)
	require.Len(t, directives, 1)
	assert.Equal(t, []string{"$x", ""}, directives[0].Args)
}

func TestParseMixOfBlockAndSimpleAtTopLevel(t *testing.T) {
	directives, err := Parse(`
user nginx;
pid /run/nginx.pid;
events { worker_connections 1024; }
worker_processes auto;
http { }
`)
	require.NoError(t, err)
	require.Len(t, directives, 5)
	assert.Equal(t, []string{"user", "pid", "events", "worker_processes", "http"},
		[]string{
			directives[0].Name, directives[1].Name, directives[2].Name,
			directives[3].Name, directives[4].Name,
		})
}

// Prevents worst-case performance regressions on pathological inputs.
func TestParseLargeRepeatedBlocks(t *testing.T) {
	var b strings.Builder
	b.WriteString("http {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "    server { listen %d; server_name s%d.example.com; }\n", 10000+i, i)
	}
	b.WriteString("}\n")

	directives, err := Parse(b.String())
	require.NoError(t, err)
	require.Len(t, directives, 1)
	require.True(t, directives[0].IsBlock())
	require.Len(t, directives[0].Block, 500)
}

// Ensures the tokenizer/parser don't loop forever on a garbage blob.
func TestParseDoesNotHangOnBinaryInput(t *testing.T) {
	garbage := strings.Repeat("\x00\x01\x02\x03\x04\xff\xfe", 1024)
	_, _ = Parse(garbage)
	// No assertion needed — we only care that Parse returns.
}

// Demonstrates inlined include inside a nested block.
func TestParseFilesIncludeInsideServerBlock(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
http {
    server {
        listen 80;
        include /etc/nginx/snippets/proxy-defaults.conf;
        location / { proxy_pass http://backend; }
    }
}
`,
		"/etc/nginx/snippets/proxy-defaults.conf": `
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_read_timeout 60s;
`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)
	require.Empty(t, cfg.Errors)

	// Navigate: http[0] -> server[0] -> block
	httpBlock := cfg.Directives[0]
	server := httpBlock.Block[0]
	require.True(t, server.IsBlock())

	// Expect: listen, proxy_set_header (x2), proxy_read_timeout, location
	names := make([]string, 0, len(server.Block))
	for _, d := range server.Block {
		names = append(names, d.Name)
	}
	assert.Equal(t, []string{
		"listen",
		"proxy_set_header",
		"proxy_set_header",
		"proxy_read_timeout",
		"location",
	}, names)
}

// Ensures include preserves line numbers of surrounding directives; the
// resource layer uses these for traceability.
func TestParseFilesPreservesLineNumbersOfHostingFile(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/nginx.conf": "\n\nworker_processes 1;\ninclude /part.conf;\nevents { }\n",
		"/part.conf":  "user nginx;",
	}}
	cfg, err := ParseFiles("/nginx.conf", fs.open, nil)
	require.NoError(t, err)
	require.Empty(t, cfg.Errors)

	// worker_processes from /nginx.conf line 3, user from /part.conf line 1,
	// events from /nginx.conf line 5.
	require.Len(t, cfg.Directives, 3)
	assert.Equal(t, "worker_processes", cfg.Directives[0].Name)
	assert.Equal(t, 3, cfg.Directives[0].Line)
	assert.Equal(t, "user", cfg.Directives[1].Name)
	assert.Equal(t, 1, cfg.Directives[1].Line)
	assert.Equal(t, "events", cfg.Directives[2].Name)
	assert.Equal(t, 5, cfg.Directives[2].Line)
}

// Ensures the errorList wrapper produces a useful single-line summary
// when multiple errors pile up.
func TestErrorListFormatsMultipleErrors(t *testing.T) {
	// Three stray '}' at top level — each produces its own error.
	_, err := Parse(`} } }`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse errors")
	assert.Contains(t, err.Error(), "first:")
}

// Ensures the errorList wrapper shows a single error plainly (no "first:"
// prefix when there is only one).
func TestErrorListFormatsSingleError(t *testing.T) {
	_, err := Parse(`server { listen 80 }`) // only one missing ';'
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing ';'")
	assert.NotContains(t, err.Error(), "parse errors")
}

// Quoted text retains surrounding content verbatim even when it contains
// unbalanced braces — the quote suppresses block detection.
func TestParseQuotedBracesDoNotOpenBlock(t *testing.T) {
	directives, err := Parse(`set $x "{{{"; set $y "}}}";`)
	require.NoError(t, err)
	require.Len(t, directives, 2)
	assert.Equal(t, []string{"$x", "{{{"}, directives[0].Args)
	assert.Equal(t, []string{"$y", "}}}"}, directives[1].Args)
}

// nginx refuses to start when an included file cannot be read. The parse
// carries on, but the refusal must stay recognisable so the resource can
// report it instead of a configuration without that file.
func TestParseFilesUnreadableIncludeKeepsCause(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf":    "http {\n    include /etc/nginx/conf.d/*.conf;\n}\ninclude /etc/nginx/missing.conf;\n",
		"/etc/nginx/conf.d/a.conf": "server { listen 80; }\n",
	}}
	open := func(path string) (io.ReadCloser, error) {
		if path == "/etc/nginx/conf.d/sweep-http.conf" {
			return nil, &iofs.PathError{Op: "open", Path: path, Err: iofs.ErrPermission}
		}
		return fs.open(path)
	}
	glob := memGlob{"/etc/nginx/conf.d/*.conf": {"/etc/nginx/conf.d/a.conf", "/etc/nginx/conf.d/sweep-http.conf"}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", open, glob.expand)
	require.NoError(t, err)
	require.Len(t, cfg.Errors, 2)

	var refused []ParseError
	for _, e := range cfg.Errors {
		if errors.Is(e, iofs.ErrPermission) {
			refused = append(refused, e)
		}
	}
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Error(), "/etc/nginx/conf.d/sweep-http.conf")
}
