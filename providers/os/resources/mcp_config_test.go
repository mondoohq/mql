// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures under testdata/ai-tools/linux-home were written by each agent's
// own `mcp add` command (a stdio "fs" server with an env var and an http
// "remote" server with an Authorization header), then had the secret values
// replaced with <redacted>.
const aiToolsHome = "testdata/ai-tools/linux-home"

// mcpSpecsByName indexes specs for assertions.
func mcpSpecsByName(specs []mcpServerSpec) map[string]mcpServerSpec {
	out := make(map[string]mcpServerSpec, len(specs))
	for _, s := range specs {
		out[s.name] = s
	}
	return out
}

// assertFsAndRemote checks the two servers every fixture declares, in the
// shape the tool wrote them.
func assertFsAndRemote(t *testing.T, specs []mcpServerSpec, fsHasEnv bool) {
	t.Helper()
	byName := mcpSpecsByName(specs)
	require.Len(t, byName, 2)

	fs := byName["fs"]
	assert.Equal(t, mcpTransportStdio, fs.transport)
	assert.Equal(t, "npx", fs.command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, fs.args)
	assert.Equal(t, fsHasEnv, fs.hasEnv)
	assert.False(t, fs.hasHeaders)
	assert.Empty(t, fs.url)

	remote := byName["remote"]
	assert.Equal(t, mcpTransportHTTP, remote.transport)
	assert.Equal(t, "https://mcp.example.com/mcp", remote.url)
	assert.Empty(t, remote.command)
	assert.True(t, remote.hasHeaders)
	assert.False(t, remote.hasEnv)
}

func TestReadMcpServersFileAgentFormats(t *testing.T) {
	afs := testAfero()
	tests := []struct {
		name     string
		path     string
		key      string
		fsHasEnv bool
	}{
		// Plain shape: command/args/env, url/headers with type "http".
		{"gemini", ".gemini/settings.json", "mcpServers", true},
		// Remote server written as httpUrl without a type.
		{"qwen", ".qwen/settings.json", "mcpServers", true},
		// Stdio server written with type "local".
		{"copilot cli", ".copilot/mcp-config.json", "mcpServers", true},
		// Explicit type "stdio" and "http".
		{"augment", ".augment/settings.json", "mcpServers", true},
		// transport as a string, type null, enabled true.
		{"openhands", ".openhands/mcp.json", "mcpServers", true},
		// The whole definition nested under transport, "streamableHttp".
		{"cline cli", ".cline/data/settings/cline_mcp_settings.json", "mcpServers", false},
		// command as an array, environment instead of env, type local/remote.
		{"opencode", ".config/opencode/opencode.jsonc", "mcp", true},
		{"kilo", ".config/kilo/kilo.jsonc", "mcp", true},
		// Measured: agy 1.4.7 (Antigravity CLI), macOS, 2026-10-24. Remote
		// server written as serverUrl, every server with an explicit disabled.
		{"antigravity cli", ".gemini/config/mcp_config.json", "mcpServers", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(aiToolsHome, tc.path)
			specs, err := readMcpServersFile(afs, path, tc.key)
			require.NoError(t, err)
			assertFsAndRemote(t, specs, tc.fsHasEnv)
			for _, s := range specs {
				assert.Equal(t, path, s.source)
			}
		})
	}
}

func TestReadMcpServersFileEnabled(t *testing.T) {
	// `openhands mcp disable remote` wrote "enabled": false.
	specs, err := readMcpServersFile(testAfero(), filepath.Join(aiToolsHome, ".openhands", "mcp.json"), "mcpServers")
	require.NoError(t, err)
	byName := mcpSpecsByName(specs)
	assert.True(t, byName["fs"].enabled)
	assert.False(t, byName["remote"].enabled)

	// Roo and Cline's VS Code extension write "disabled": true instead.
	specs, err = parseMcpServersJSON([]byte(`{"mcpServers":{"a":{"command":"x","disabled":true},"b":{"command":"y","disabled":false}}}`), "mcpServers", "f")
	require.NoError(t, err)
	byName = mcpSpecsByName(specs)
	assert.False(t, byName["a"].enabled)
	assert.True(t, byName["b"].enabled)

	// Measured: `agy mcp add off uvx some-server` then `agy mcp disable off`,
	// agy 1.4.7, macOS, 2026-10-24.
	specs, err = parseMcpServersJSON([]byte(`{"mcpServers":{"off":{"args":["some-server"],"command":"uvx","disabled":true}}}`), "mcpServers", "f")
	require.NoError(t, err)
	assert.False(t, mcpSpecsByName(specs)["off"].enabled)
}

// Synthetic: url wins over serverUrl when a file carries both; no tool wrote
// this.
func TestParseMcpServersJSONServerURLPrecedence(t *testing.T) {
	specs, err := parseMcpServersJSON([]byte(`{"mcpServers":{"a":{"url":"https://u.example/mcp","serverUrl":"https://s.example/mcp"}}}`), "mcpServers", "f")
	require.NoError(t, err)
	assert.Equal(t, "https://u.example/mcp", mcpSpecsByName(specs)["a"].url)
}

func TestReadMcpServersFileMissingAndMalformed(t *testing.T) {
	specs, err := readMcpServersFile(testAfero(), filepath.Join(t.TempDir(), "mcp.json"), "mcpServers")
	require.NoError(t, err)
	assert.Empty(t, specs)

	dir := t.TempDir()
	writeTestFile(t, dir, "mcp.json", `{"mcpServers": [`)
	_, err = readMcpServersFile(testAfero(), filepath.Join(dir, "mcp.json"), "mcpServers")
	assert.Error(t, err)
}

// A plugin's .mcp.json comes wrapped in mcpServers (context7) or as the bare
// server map (github), both from installed Claude Code plugins.
func TestParseMcpServersJSONPluginShapes(t *testing.T) {
	afs := testAfero()

	wrapped, err := readMcpServersFile(afs, "testdata/ai-tools/claude-code/context7/.mcp.json", "")
	require.NoError(t, err)
	require.Len(t, wrapped, 1)
	assert.Equal(t, "context7", wrapped[0].name)
	assert.Equal(t, mcpTransportHTTP, wrapped[0].transport)
	assert.Equal(t, "https://mcp.context7.com/mcp?client=claude-code-plugin", wrapped[0].url)

	flat, err := readMcpServersFile(afs, "testdata/ai-tools/claude-code/github/.mcp.json", "")
	require.NoError(t, err)
	require.Len(t, flat, 1)
	assert.Equal(t, "github", flat[0].name)
	assert.Equal(t, "https://api.githubcopilot.com/mcp/", flat[0].url)
	assert.True(t, flat[0].hasHeaders)
}

// VS Code's user mcp.json keeps servers under `servers`.
func TestReadMcpServersFileVSCode(t *testing.T) {
	specs, err := readMcpServersFile(testAfero(), "testdata/ai-tools/vscode/mcp.json", "servers")
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "Neon", specs[0].name)
	assert.Equal(t, mcpTransportHTTP, specs[0].transport)
	assert.Equal(t, "https://mcp.neon.tech/mcp", specs[0].url)
	assert.True(t, specs[0].hasHeaders)
}

func TestDeriveMcpTransportFoldsSpellings(t *testing.T) {
	for explicit, want := range map[string]string{
		"local":           mcpTransportStdio, // Copilot CLI, OpenCode
		"stdio":           mcpTransportStdio,
		"remote":          mcpTransportHTTP, // OpenCode
		"streamableHttp":  mcpTransportHTTP, // Cline
		"streamable-http": mcpTransportHTTP, // Mistral Vibe
		"streamable_http": mcpTransportHTTP, // Goose
		"HTTP":            mcpTransportHTTP,
		"sse":             "sse",
	} {
		assert.Equal(t, want, deriveMcpTransport(explicit, "", ""), explicit)
	}
}

func TestExpandPlaceholder(t *testing.T) {
	s := mcpServerSpec{
		command: "${extensionPath}/osv-scanner",
		args:    []string{"${extensionPath}/index.js", "${user_config.dirs}"},
	}
	out := s.expandPlaceholder("extensionPath", "/home/alice/.gemini/extensions/sec")
	assert.Equal(t, "/home/alice/.gemini/extensions/sec/osv-scanner", out.command)
	assert.Equal(t, []string{"/home/alice/.gemini/extensions/sec/index.js", "${user_config.dirs}"}, out.args)
	// The original spec is not modified.
	assert.Equal(t, "${extensionPath}/index.js", s.args[0])
}

func TestMcpServerResourceIDKeysBySource(t *testing.T) {
	assert.NotEqual(t,
		mcpServerResourceID("opencode.mcpServer", "/home/a/.config/opencode/opencode.json", "fs"),
		mcpServerResourceID("opencode.mcpServer", "/home/a/.config/opencode/opencode.jsonc", "fs"))
}
