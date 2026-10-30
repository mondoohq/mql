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

// testdata/ai-tools/claude-desktop holds the app's extensions-installations.json
// (trimmed to three extensions) and the per-extension settings files it wrote:
// filesystem enabled, panos-mcp disabled, pdf-server-mcp with no settings file.
const claudeDesktopTestdata = "testdata/ai-tools/claude-desktop"

func TestReadClaudeDesktopExtensions(t *testing.T) {
	exts, enabled, err := readClaudeDesktopExtensions(testAfero(), claudeDesktopTestdata)
	require.NoError(t, err)
	require.Len(t, exts, 3)

	// Sorted by id.
	assert.Equal(t, "ant.dir.ant.anthropic.filesystem", exts[0].ID)
	assert.Equal(t, "ant.dir.gh.anthropic.pdf-server-mcp", exts[1].ID)
	assert.Equal(t, "ant.dir.gh.apius-tech.panos-mcp", exts[2].ID)

	assert.True(t, enabled["ant.dir.ant.anthropic.filesystem"])
	assert.False(t, enabled["ant.dir.gh.apius-tech.panos-mcp"], "isEnabled false in its settings file")
	assert.True(t, enabled["ant.dir.gh.anthropic.pdf-server-mcp"], "no settings file means enabled")

	fsExt := exts[0]
	assert.Equal(t, "registry", fsExt.Source)
	assert.Equal(t, "unsigned", fsExt.SignatureInfo.Status)
	assert.Equal(t, "2026.7.10", fsExt.Manifest.Version)
	assert.Equal(t, "Anthropic", pluginAuthorName(fsExt.Manifest.Author))
	assert.Equal(t, "read_file", fsExt.Manifest.Tools[0].Name)
	assert.NotNil(t, parseRFC3339Ptr(fsExt.InstalledAt))
}

// An extension's server substitutes ${__dirname} with its directory and keeps
// ${user_config.*} placeholders, whose values the user entered.
func TestClaudeDesktopExtensionMcpServer(t *testing.T) {
	exts, _, err := readClaudeDesktopExtensions(testAfero(), claudeDesktopTestdata)
	require.NoError(t, err)
	dir := "/Users/alice/Library/Application Support/Claude/Claude Extensions/ant.dir.ant.anthropic.filesystem"

	fs := exts[0].mcpServer(dir)
	assert.Equal(t, "ant.dir.ant.anthropic.filesystem", fs.name)
	assert.Equal(t, mcpTransportStdio, fs.transport)
	assert.Equal(t, "node", fs.command)
	assert.Equal(t, []string{dir + "/dist/index.js", "${user_config.allowed_directories}"}, fs.args)
	assert.False(t, fs.hasEnv)

	// panos-mcp passes its API key through env from user_config.
	assert.True(t, exts[2].mcpServer("/x").hasEnv)
	// pdf-server declares an empty env object.
	assert.False(t, exts[1].mcpServer("/x").hasEnv)
}

func TestReadClaudeDesktopExtensionsMissingAndMalformed(t *testing.T) {
	exts, _, err := readClaudeDesktopExtensions(testAfero(), t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, exts)

	dir := t.TempDir()
	writeTestFile(t, dir, claudeDesktopExtensionsFile, `{"extensions": [`)
	_, _, err = readClaudeDesktopExtensions(testAfero(), dir)
	assert.Error(t, err)
}
