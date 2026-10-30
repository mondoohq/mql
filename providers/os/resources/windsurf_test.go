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

func createTestWindsurfConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	mkdirAllTest(t, dir, "memories")
	writeTestFile(t, dir, "memories/global_rules.md", `# Global Rules

Always write tests for new code.
`)

	writeTestFile(t, dir, "mcp_config.json", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem"],
				"env": {}
			},
			"remote": {
				"serverUrl": "https://mcp.example.com/sse"
			}
		}
	}`)

	return dir
}

func TestWindsurfRulesParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestWindsurfConfig(t)

	entries, err := afs.ReadDir(filepath.Join(dir, "memories"))
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	data, err := afs.ReadFile(filepath.Join(dir, "memories", "global_rules.md"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "Always write tests for new code")
}

func TestWindsurfMCPParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestWindsurfConfig(t)

	data, err := afs.ReadFile(filepath.Join(dir, "mcp_config.json"))
	require.NoError(t, err)

	var config windsurfMCPConfig
	err = json.Unmarshal(data, &config)
	require.NoError(t, err)
	assert.Len(t, config.McpServers, 2)

	fs := config.McpServers["filesystem"]
	assert.Equal(t, "npx", fs.Command)
	assert.Empty(t, fs.Env)
	assert.Equal(t, mcpTransportStdio, deriveMcpTransport(fs.Type, fs.Command, fs.URL))

	// remote server uses serverUrl; the creator falls back to it for url
	remote := config.McpServers["remote"]
	assert.Equal(t, "https://mcp.example.com/sse", remote.ServerURL)
	assert.Empty(t, remote.Command)
}

func TestWindsurfConfigMissing(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	_, err := afs.ReadDir(filepath.Join(dir, "memories"))
	assert.Error(t, err)
}
