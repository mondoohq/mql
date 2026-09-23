// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaudeDesktopConfigDir(t *testing.T) {
	assert.Equal(t, filepath.Join("/Users/alice", "Library", "Application Support", "Claude"), claudeDesktopConfigDir("/Users/alice", "darwin"))
	assert.Equal(t, filepath.Join(`C:\Users\alice`, "AppData", "Roaming", "Claude"), claudeDesktopConfigDir(`C:\Users\alice`, "windows"))
	assert.Equal(t, filepath.Join("/home/alice", ".config", "Claude"), claudeDesktopConfigDir("/home/alice", "linux"))
}

// claude_desktop_config.json in the shape the app writes: stdio servers with
// command/args and an optional env block holding secrets.
func TestClaudeDesktopMCPServers(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "claude_desktop_config.json", `{
		"mcpServers": {
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"],
				"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "<redacted>"}
			},
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/Desktop"]
			}
		}
	}`)

	servers, err := claudeDesktopMCPServers(testAfero(), dir)
	require.NoError(t, err)
	require.Len(t, servers, 2)
	assert.Equal(t, "npx", servers["github"].Command)
	assert.Len(t, servers["github"].Env, 1)
	assert.Empty(t, servers["filesystem"].Env)
	assert.Equal(t, mcpTransportStdio, deriveMcpTransport(servers["filesystem"].Type, servers["filesystem"].Command, servers["filesystem"].URL))
}

func TestClaudeDesktopMCPServersMissingAndMalformed(t *testing.T) {
	servers, err := claudeDesktopMCPServers(testAfero(), t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, servers)

	dir := t.TempDir()
	writeTestFile(t, dir, "claude_desktop_config.json", `{"mcpServers": [`)
	_, err = claudeDesktopMCPServers(testAfero(), dir)
	assert.Error(t, err)
}
