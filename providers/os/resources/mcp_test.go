// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestDeriveMcpTransport(t *testing.T) {
	tests := []struct {
		name         string
		explicitType string
		command      string
		url          string
		want         string
	}{
		{name: "explicit wins over inference", explicitType: "sse", command: "npx", url: "https://x", want: "sse"},
		{name: "command implies stdio", command: "npx", want: mcpTransportStdio},
		{name: "url implies http", url: "https://mcp.example.com/mcp", want: mcpTransportHTTP},
		{name: "command preferred when both present", command: "npx", url: "https://x", want: mcpTransportStdio},
		{name: "nothing set", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deriveMcpTransport(tt.explicitType, tt.command, tt.url))
		})
	}
}

func TestMcpArgsData(t *testing.T) {
	rd := mcpArgsData([]string{"-y", "server", "/tmp"})
	arr, ok := rd.Value.([]any)
	assert.True(t, ok)
	assert.Equal(t, []any{"-y", "server", "/tmp"}, arr)

	// Synthetic: a secret passed on the command line is redacted.
	rd = mcpArgsData([]string{"server", "--api-key", "abc123"})
	assert.Equal(t, []any{"server", "--api-key", redactedValue}, rd.Value)

	// nil slice yields an empty, non-nil array
	empty := mcpArgsData(nil)
	emptyArr, ok := empty.Value.([]any)
	assert.True(t, ok)
	assert.Empty(t, emptyArr)
}

func TestParseMcpLaunch(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		launcher string
		pkg      string
		pinned   bool
	}{
		// Synthetic: npm spec forms; no target showed this.
		{name: "npx exact scoped version", command: "npx", args: []string{"-y", "@scope/pkg@1.2.3"},
			launcher: "npx", pkg: "@scope/pkg", pinned: true},
		{name: "npx latest tag", command: "npx", args: []string{"-y", "@scope/pkg@latest"},
			launcher: "npx", pkg: "@scope/pkg"},
		{name: "npx caret range", command: "npx", args: []string{"--yes", "pkg@^1.2"},
			launcher: "npx", pkg: "pkg"},
		{name: "npx no version", command: "npx", args: []string{"-y", "@scope/pkg", "/tmp"},
			launcher: "npx", pkg: "@scope/pkg"},
		{name: "npx package flag", command: "npx", args: []string{"-p", "pkg@2.0.0", "pkg-cli"},
			launcher: "npx", pkg: "pkg", pinned: true},
		{name: "npx windows shim with path", command: `C:\Program Files\nodejs\npx.cmd`, args: []string{"-y", "pkg@1.0.0"},
			launcher: "npx", pkg: "pkg", pinned: true},
		{name: "pnpm dlx", command: "pnpm", args: []string{"dlx", "pkg@3.1.4"},
			launcher: "pnpm dlx", pkg: "pkg", pinned: true},
		{name: "yarn dlx", command: "yarn", args: []string{"dlx", "pkg"},
			launcher: "yarn dlx", pkg: "pkg"},
		{name: "bunx", command: "bunx", args: []string{"pkg@1.0.0-beta.1"},
			launcher: "bunx", pkg: "pkg", pinned: true},
		// Synthetic: PyPI spec forms; no target showed this.
		{name: "uvx from exact", command: "uvx", args: []string{"--from", "pkg==1.0", "pkg-server"},
			launcher: "uvx", pkg: "pkg", pinned: true},
		{name: "uvx at version", command: "uvx", args: []string{"mcp-server-fetch@2025.1.17"},
			launcher: "uvx", pkg: "mcp-server-fetch", pinned: true},
		{name: "uvx at latest", command: "uvx", args: []string{"mcp-server-fetch@latest"},
			launcher: "uvx", pkg: "mcp-server-fetch"},
		{name: "uvx range", command: "uvx", args: []string{"--from", "pkg>=1.0", "pkg"},
			launcher: "uvx", pkg: "pkg"},
		{name: "uvx wildcard", command: "uvx", args: []string{"--from", "pkg==1.*", "pkg"},
			launcher: "uvx", pkg: "pkg"},
		{name: "uvx extras exact", command: "uvx", args: []string{"--python", "3.12", "pkg[cli]==0.4.1"},
			launcher: "uvx", pkg: "pkg", pinned: true},
		{name: "uv tool run", command: "uv", args: []string{"tool", "run", "pkg==1.0.0"},
			launcher: "uvx", pkg: "pkg", pinned: true},
		{name: "pipx run spec", command: "pipx", args: []string{"run", "--spec", "pkg==1.0.0", "pkg"},
			launcher: "pipx run", pkg: "pkg", pinned: true},
		{name: "pipx run at is not a version", command: "pipx", args: []string{"run", "pkg@1.0.0"},
			launcher: "pipx run", pkg: "pkg"},
		// Synthetic: container image references; no target showed this.
		{name: "docker tag", command: "docker", args: []string{"run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/x/y:1.0"},
			launcher: "docker run", pkg: "ghcr.io/x/y"},
		{name: "docker digest", command: "docker",
			args:     []string{"run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/x/y:1.0@sha256:" + strings.Repeat("ab", 32)},
			launcher: "docker run", pkg: "ghcr.io/x/y", pinned: true},
		{name: "docker short digest is not pinned", command: "docker", args: []string{"run", "ghcr.io/x/y@sha256:abc"},
			launcher: "docker run", pkg: "ghcr.io/x/y"},
		{name: "docker registry port", command: "docker", args: []string{"run", "--env=A=b", "localhost:5000/img"},
			launcher: "docker run", pkg: "localhost:5000/img"},
		{name: "podman container run", command: "podman", args: []string{"container", "run", "-it", "img:2"},
			launcher: "podman run", pkg: "img"},
		{name: "docker exec is not a launcher", command: "docker", args: []string{"exec", "-i", "box", "srv"}},
		// Synthetic: commands that are not package runners.
		{name: "plain binary", command: "/usr/local/bin/mcp-server", args: []string{"--port", "1"}},
		{name: "node script", command: "node", args: []string{"server.js"}},
		{name: "pnpm without dlx", command: "pnpm", args: []string{"exec", "pkg"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMcpLaunch(tt.command, tt.args)
			assert.Equal(t, mcpLaunch{launcher: tt.launcher, packageName: tt.pkg, pinned: tt.pinned}, got)
		})
	}
}

// Synthetic: packagePinned is null without a launcher or package, a bool
// otherwise; no target showed this.
func TestSetMcpServerShape(t *testing.T) {
	fields := map[string]*llx.RawData{}
	setMcpServerShape(fields, "/usr/local/bin/srv", nil, "", []string{"B", "A"}, []string{"A"})
	assert.Nil(t, fields["packagePinned"].Value, "no launcher means pinned is null")
	assert.Equal(t, types.Bool, fields["packagePinned"].Type)
	assert.Equal(t, "", fields["launcher"].Value)
	assert.Equal(t, []any{"A", "B"}, fields["envNames"].Value, "env names are merged, deduplicated and sorted")

	fields = map[string]*llx.RawData{}
	setMcpServerShape(fields, "npx", []string{"-y"}, "", nil)
	assert.Nil(t, fields["packagePinned"].Value, "a launcher without a package means pinned is null")
	assert.Equal(t, []any{}, fields["envNames"].Value)

	fields = map[string]*llx.RawData{}
	setMcpServerShape(fields, "npx", []string{"-y", "pkg@latest"}, "http://mcp.example.com", nil)
	assert.Equal(t, false, fields["packagePinned"].Value)
	assert.Equal(t, "npx", fields["launcher"].Value)
	assert.Equal(t, "pkg", fields["packageName"].Value)
	assert.Equal(t, true, fields["insecureTransport"].Value)
}

func TestMcpInsecureTransport(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		// Synthetic: loopback, remote and TLS endpoints; no target showed this.
		{"http://localhost:3000/mcp", false},
		{"http://127.0.0.1:8080/mcp", false},
		{"http://127.0.0.2/mcp", false},
		{"http://[::1]:8080/mcp", false},
		{"http://mcp.localhost/mcp", false},
		{"http://example.com/mcp", true},
		{"HTTP://Example.com/mcp", true},
		{"http://10.0.0.5:8080/mcp", true},
		{"https://example.com/mcp", false},
		{"", false},
		{"not a url", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, mcpInsecureTransport(tt.url))
		})
	}
}

// Synthetic: names from several maps are merged; no target showed this.
func TestMcpNamesSortedAndDeduplicated(t *testing.T) {
	assert.Equal(t, []string{"A_KEY", "B_KEY", "Z_KEY"},
		mcpNames([]string{"Z_KEY", "A_KEY"}, mapKeys(map[string]string{"B_KEY": "v", "A_KEY": "w", "": "x"})))
	assert.Equal(t, []string{}, mcpNames(nil))
}
