// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nginx

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serverDirectiveArgs collects, per server block, the "name=args" of each
// directive inside it, so a test can assert what a given server actually got.
func serverDirectiveArgs(dirs []Directive) [][]string {
	var out [][]string
	var walk func(ds []Directive)
	walk = func(ds []Directive) {
		for _, d := range ds {
			if d.Name == "server" && d.IsBlock() {
				var got []string
				for _, c := range d.Block {
					got = append(got, c.Name+"="+fmt.Sprint(c.Args))
				}
				out = append(out, got)
			}
			if d.IsBlock() {
				walk(d.Block)
			}
		}
	}
	walk(dirs)
	return out
}

// The canonical Debian/Ubuntu nginx layout has several server blocks include
// the same TLS snippet. A whole-run "visited" set treated the second include
// as a cycle and dropped it, so every server past the first silently lost its
// TLS policy.
func TestParseFiles_SameSnippetIncludedByTwoServers(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
http {
    server { listen 443 ssl; server_name a.example.com; include /etc/nginx/snippets/ssl.conf; }
    server { listen 443 ssl; server_name b.example.com; include /etc/nginx/snippets/ssl.conf; }
}
`,
		"/etc/nginx/snippets/ssl.conf": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL;\n",
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)

	servers := serverDirectiveArgs(cfg.Directives)
	require.Len(t, servers, 2)

	for i, got := range servers {
		assert.Contains(t, got, "ssl_protocols=[TLSv1.2 TLSv1.3]", "server %d missing ssl_protocols", i)
		assert.Contains(t, got, "ssl_ciphers=[HIGH:!aNULL]", "server %d missing ssl_ciphers", i)
	}

	// The snippet is listed once even though it was included twice.
	assert.ElementsMatch(t, []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/snippets/ssl.conf",
	}, cfg.Files)
}

// The same file included twice in sequence at the same level must be expanded
// both times.
func TestParseFiles_RepeatedIncludeAtSameLevel(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf":  "include /etc/nginx/common.conf;\ninclude /etc/nginx/common.conf;\n",
		"/etc/nginx/common.conf": "keepalive_timeout 60;\n",
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)

	count := 0
	for _, d := range cfg.Directives {
		if d.Name == "keepalive_timeout" {
			count++
		}
	}
	assert.Equal(t, 2, count, "an include repeated at the same level expands both times")
}

// A snippet that itself includes a shared sub-snippet, pulled in by two
// servers, must resolve fully both times.
func TestParseFiles_NestedRepeatedInclude(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `
http {
    server { include /etc/nginx/a.conf; }
    server { include /etc/nginx/a.conf; }
}
`,
		"/etc/nginx/a.conf": "include /etc/nginx/b.conf;\n",
		"/etc/nginx/b.conf": "ssl_protocols TLSv1.3;\n",
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err)

	servers := serverDirectiveArgs(cfg.Directives)
	require.Len(t, servers, 2)
	for i, got := range servers {
		assert.Equal(t, []string{"ssl_protocols=[TLSv1.3]"}, got, "server %d", i)
	}
}

// A file that includes itself must still be caught, and must not hang.
func TestParseFiles_SelfIncludeStillDetected(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": "worker_processes 4;\ninclude /etc/nginx/nginx.conf;\n",
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err, "a self-including config must not hang")
	assert.Equal(t, []string{"/etc/nginx/nginx.conf"}, cfg.Files)

	count := 0
	for _, d := range cfg.Directives {
		if d.Name == "worker_processes" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// A mutual include cycle across three files must terminate.
func TestParseFiles_MutualCycleStillDetected(t *testing.T) {
	fs := &memFS{files: map[string]string{
		"/etc/nginx/nginx.conf": `include /etc/nginx/a.conf;`,
		"/etc/nginx/a.conf":     `include /etc/nginx/b.conf;`,
		"/etc/nginx/b.conf":     `include /etc/nginx/a.conf;`,
	}}

	cfg, err := ParseFiles("/etc/nginx/nginx.conf", fs.open, nil)
	require.NoError(t, err, "cyclical includes must not hang")
	assert.ElementsMatch(t, []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/a.conf",
		"/etc/nginx/b.conf",
	}, cfg.Files)
}

// A deep but acyclic include chain is bounded rather than exhausting the stack.
func TestParseFiles_DepthCap(t *testing.T) {
	files := map[string]string{}
	total := maxIncludeDepth + 10
	for i := range total {
		files[fmt.Sprintf("/etc/nginx/%d.conf", i)] = fmt.Sprintf("include /etc/nginx/%d.conf;\n", i+1)
	}
	files[fmt.Sprintf("/etc/nginx/%d.conf", total)] = "worker_processes 1;\n"
	fs := &memFS{files: files}

	// The root read succeeds; the depth cap surfaces as an error rather than
	// a crash.
	_, err := ParseFiles("/etc/nginx/0.conf", fs.open, nil)
	require.NoError(t, err, "the depth cap is reported per-include, not as a root failure")
}
