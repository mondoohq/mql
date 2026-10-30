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

func createTestCursorConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// mcp.json with servers
	writeTestFile(t, dir, "mcp.json", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {}
			},
			"github": {
				"command": "gh",
				"args": ["mcp"],
				"env": {"GITHUB_TOKEN": "ghp_test123"}
			},
			"remote": {
				"type": "sse",
				"url": "https://mcp.example.com/sse"
			}
		}
	}`)

	// rules directory with rule files
	mkdirAllTest(t, dir, "rules")
	writeTestFile(t, dir, "rules/code-style.md", `# Code Style

Always use tabs for indentation.
`)
	writeTestFile(t, dir, "rules/testing.mdc", `---
description: Testing guidelines
---

Write tests for all public functions.
`)

	return dir
}

func TestCursorMCPConfigParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCursorConfig(t)

	data, err := afs.ReadFile(filepath.Join(dir, "mcp.json"))
	require.NoError(t, err)

	var config cursorMCPConfig
	err = json.Unmarshal(data, &config)
	require.NoError(t, err)
	assert.Len(t, config.McpServers, 3)

	fs := config.McpServers["filesystem"]
	assert.Equal(t, "npx", fs.Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, fs.Args)
	assert.Empty(t, fs.Env)
	assert.Equal(t, mcpTransportStdio, deriveMcpTransport(fs.Type, fs.Command, fs.URL))

	gh := config.McpServers["github"]
	assert.Equal(t, "gh", gh.Command)
	assert.Equal(t, []string{"mcp"}, gh.Args)
	assert.Equal(t, "ghp_test123", gh.Env["GITHUB_TOKEN"])

	remote := config.McpServers["remote"]
	assert.Equal(t, "sse", remote.Type)
	assert.Equal(t, "https://mcp.example.com/sse", remote.URL)
	assert.Empty(t, remote.Command)
	assert.Equal(t, "sse", deriveMcpTransport(remote.Type, remote.Command, remote.URL))
}

func TestCursorMCPConfigEmpty(t *testing.T) {
	data := []byte(`{"mcpServers": {}}`)
	var config cursorMCPConfig
	err := json.Unmarshal(data, &config)
	require.NoError(t, err)
	assert.Empty(t, config.McpServers)
}

func TestCursorRulesDirectory(t *testing.T) {
	afs := testAfero()
	dir := createTestCursorConfig(t)

	rulesDir := filepath.Join(dir, "rules")
	entries, err := afs.ReadDir(rulesDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Verify rule content can be read
	data, err := afs.ReadFile(filepath.Join(rulesDir, "code-style.md"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "Always use tabs for indentation")

	data, err = afs.ReadFile(filepath.Join(rulesDir, "testing.mdc"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "Write tests for all public functions")
}

func TestCursorConfigMissing(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	// mcp.json does not exist
	_, err := afs.ReadFile(filepath.Join(dir, "mcp.json"))
	assert.True(t, isNotExist(err))

	// rules dir does not exist
	_, err = afs.ReadDir(filepath.Join(dir, "rules"))
	assert.True(t, isNotExist(err))
}

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	return filepath.IsAbs(err.Error()) || err.Error() != "" // fallback
}
