// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Plugin directories under testdata/ai-tools/claude-code were copied from
// installed Claude Code plugins, keeping their manifests and file layout.
const claudePluginsTestdata = "testdata/ai-tools/claude-code"

// vercel lists its commands and agents in the manifest, ships .md.tmpl
// sources next to them and a commands/_conventions.md the manifest does not
// list, keeps hooks in the default hooks/hooks.json and its MCP server in
// the default .mcp.json.
func TestReadAgentPluginManifestPaths(t *testing.T) {
	dir := filepath.Join(claudePluginsTestdata, "vercel")
	p := readAgentPlugin(testAfero(), dir, claudePluginRootVar)

	assert.Equal(t, "vercel", p.manifest.Name)
	assert.Equal(t, "0.50.0", p.manifest.Version)
	assert.Equal(t, "Vercel", p.author)
	assert.Equal(t, "https://github.com/vercel/vercel-plugin", p.repository)
	assert.Equal(t, "Apache-2.0", p.manifest.License)
	assert.Equal(t, []string{"bootstrap", "deploy", "env", "status"}, p.commands, "the manifest list wins over the directory")
	assert.Equal(t, []string{"ai-architect", "deployment-expert", "performance-optimizer"}, p.agents)
	assert.True(t, p.hasHooks)
	assert.Equal(t, []string{filepath.Join(dir, "skills")}, p.skillsDirs)

	require.Len(t, p.mcpServers, 1)
	assert.Equal(t, "vercel", p.mcpServers[0].name)
	assert.Equal(t, "https://mcp.vercel.com", p.mcpServers[0].url)
	assert.Equal(t, filepath.Join(dir, ".mcp.json"), p.mcpServers[0].source)
}

// chrome-devtools-mcp declares its MCP server inline in plugin.json and has
// no author, commands, agents or hooks.
func TestReadAgentPluginInlineMcpServers(t *testing.T) {
	dir := filepath.Join(claudePluginsTestdata, "chrome-devtools-mcp")
	p := readAgentPlugin(testAfero(), dir, claudePluginRootVar)

	require.Len(t, p.mcpServers, 1)
	assert.Equal(t, "chrome-devtools", p.mcpServers[0].name)
	assert.Equal(t, mcpTransportStdio, p.mcpServers[0].transport)
	assert.Equal(t, "npx", p.mcpServers[0].command)
	assert.Equal(t, filepath.Join(dir, ".claude-plugin", "plugin.json"), p.mcpServers[0].source)
	assert.Empty(t, p.author)
	assert.Empty(t, p.commands)
	assert.Empty(t, p.agents)
	assert.False(t, p.hasHooks)
}

// The azure plugin installed by the Copilot CLI is in the Claude plugin
// format and points its hooks at a non-default file.
func TestReadAgentPluginCopilotAzure(t *testing.T) {
	dir := filepath.Join(aiToolsHome, ".copilot", "installed-plugins", "awesome-copilot", "azure")
	p := readAgentPlugin(testAfero(), dir, "")

	assert.Equal(t, "Microsoft", p.author)
	assert.Equal(t, "https://github.com/microsoft/azure-skills", p.repository)
	assert.True(t, p.hasHooks, "hooks point at hooks/claude-hooks.json")
	require.Len(t, p.mcpServers, 1)
	assert.Equal(t, "azure", p.mcpServers[0].name)
	assert.Equal(t, []string{"-y", "@azure/mcp@latest", "server", "start"}, p.mcpServers[0].args)
}

func TestReadAgentPluginWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, ".mcp.json", `{"mcpServers":{"local":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/server","args":["--root","${CLAUDE_PLUGIN_ROOT}"]}}}`)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "commands"), 0o755))
	writeTestFile(t, dir, "commands/go.md", "# go")

	p := readAgentPlugin(testAfero(), dir, claudePluginRootVar)
	assert.Empty(t, p.manifest.Name)
	assert.Equal(t, []string{"go"}, p.commands)
	assert.False(t, p.hasHooks)
	require.Len(t, p.mcpServers, 1)
	assert.Equal(t, filepath.Join(dir, "bin", "server"), p.mcpServers[0].command)
	assert.Equal(t, []string{"--root", dir}, p.mcpServers[0].args)
}

func TestPluginAuthorAndRepository(t *testing.T) {
	assert.Equal(t, "Vercel", pluginAuthorName(json.RawMessage(`{"name":"Vercel","url":"https://github.com/vercel"}`)))
	assert.Equal(t, "Jane Doe", pluginAuthorName(json.RawMessage(`"Jane Doe"`)))
	assert.Empty(t, pluginAuthorName(nil))

	assert.Equal(t, "https://github.com/obra/superpowers", pluginRepositoryURL(json.RawMessage(`"https://github.com/obra/superpowers"`)))
	assert.Equal(t, "https://github.com/a/b.git", pluginRepositoryURL(json.RawMessage(`{"type":"git","url":"https://github.com/a/b.git"}`)))
	assert.Empty(t, pluginRepositoryURL(nil))
}

func TestParseRFC3339Ptr(t *testing.T) {
	ts := parseRFC3339Ptr("2026-10-23T01:16:07.856089627Z")
	require.NotNil(t, ts)
	assert.Equal(t, 856089627, ts.Nanosecond())
	assert.Nil(t, parseRFC3339Ptr(""))
	assert.Nil(t, parseRFC3339Ptr("yesterday"))
}
