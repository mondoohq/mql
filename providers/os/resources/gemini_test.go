// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestGeminiConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeTestFile(t, dir, "settings.json", `{
		"theme": "GitHub",
		"selectedAuthType": "oauth-personal"
	}`)

	mkdirAllTest(t, dir, "antigravity")
	writeTestFile(t, dir, "antigravity/mcp_config.json", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem"],
				"env": {"HOME": "/tmp"}
			},
			"remote": {
				"httpUrl": "https://mcp.example.com/mcp"
			}
		}
	}`)

	return dir
}

func TestGeminiSettingsParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestGeminiConfig(t)

	var settings geminiSettings
	err := readJSONFileAfero(afs, dir, "settings.json", &settings)
	require.NoError(t, err)
	assert.Equal(t, "oauth-personal", settings.SelectedAuthType)
	assert.Equal(t, "GitHub", settings.Theme)
}

func TestGeminiMCPParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestGeminiConfig(t)

	data, err := afs.ReadFile(filepath.Join(dir, "antigravity", "mcp_config.json"))
	require.NoError(t, err)

	var config geminiMCPConfig
	err = json.Unmarshal(data, &config)
	require.NoError(t, err)
	assert.Len(t, config.McpServers, 2)

	fs := config.McpServers["filesystem"]
	assert.Equal(t, "npx", fs.Command)
	assert.Len(t, fs.Args, 2)
	assert.Len(t, fs.Env, 1)
	assert.Equal(t, mcpTransportStdio, deriveMcpTransport(fs.Type, fs.Command, fs.URL))

	// remote server uses httpUrl; the creator falls back to it for url
	remote := config.McpServers["remote"]
	assert.Equal(t, "https://mcp.example.com/mcp", remote.HTTPURL)
	assert.Empty(t, remote.Command)
}

func TestGeminiConfigMissing(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	var settings geminiSettings
	err := readJSONFileAfero(afs, dir, "settings.json", &settings)
	assert.Error(t, err)
}

// Current Gemini CLI releases keep MCP servers under `mcpServers` in
// settings.json, next to `model.name` and `security.auth.selectedType`.
func TestGeminiMCPServersFromSettings(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()
	writeTestFile(t, dir, "settings.json", `{"model":{"name":"gemini-2.5-pro"},"security":{"auth":{"selectedType":"oauth-personal"}},"mcpServers":{"memory":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]}}}`)

	servers, err := geminiMCPServers(afs, dir)
	require.NoError(t, err)
	require.Contains(t, servers, "memory")
	assert.Equal(t, "npx", servers["memory"].Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-memory"}, servers["memory"].Args)
}

// Both files are read; a server named in both is reported with its
// settings.json definition.
func TestGeminiMCPServersMergesBothFiles(t *testing.T) {
	afs := testAfero()
	dir := createTestGeminiConfig(t) // antigravity/mcp_config.json: filesystem, remote
	writeTestFile(t, dir, "settings.json", `{"mcpServers":{
		"filesystem": {"command": "uvx", "args": ["mcp-server-filesystem"]},
		"memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}
	}}`)

	servers, err := geminiMCPServers(afs, dir)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"filesystem", "remote", "memory"}, keysOf(servers))
	assert.Equal(t, "uvx", servers["filesystem"].Command, "settings.json wins over antigravity")
	assert.Equal(t, "https://mcp.example.com/mcp", servers["remote"].HTTPURL)
}

func TestGeminiMCPServersNoFiles(t *testing.T) {
	servers, err := geminiMCPServers(testAfero(), t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, servers)
}

func TestGeminiMCPServersMalformedSettings(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "settings.json", `{"mcpServers": [`)
	_, err := geminiMCPServers(testAfero(), dir)
	assert.Error(t, err)
}

func TestGeminiAuthType(t *testing.T) {
	var nested geminiSettings
	require.NoError(t, json.Unmarshal([]byte(`{"security":{"auth":{"selectedType":"oauth-personal"}}}`), &nested))
	assert.Equal(t, "oauth-personal", nested.authType())

	var flat geminiSettings
	require.NoError(t, json.Unmarshal([]byte(`{"selectedAuthType":"gemini-api-key"}`), &flat))
	assert.Equal(t, "gemini-api-key", flat.authType())

	var both geminiSettings
	require.NoError(t, json.Unmarshal([]byte(`{"selectedAuthType":"gemini-api-key","security":{"auth":{"selectedType":"vertex-ai"}}}`), &both))
	assert.Equal(t, "vertex-ai", both.authType(), "the nested key is current and wins")

	assert.Empty(t, geminiSettings{}.authType())
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
