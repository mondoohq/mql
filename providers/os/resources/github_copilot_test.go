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

func createTestCopilotConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeTestFile(t, dir, "apps.json", `{
		"github.com:Iv23ctfURkiMfJ4xr5mv": {
			"oauth_token": "ghu_test123",
			"user": "testuser",
			"githubAppId": "Iv23ctfURkiMfJ4xr5mv"
		},
		"github.com:Ov23liV9UpD7Rnfnskm3": {
			"user": "testuser",
			"oauth_token": "gho_test456",
			"githubAppId": "Ov23liV9UpD7Rnfnskm3"
		}
	}`)

	mkdirAllTest(t, dir, "intellij")
	writeTestFile(t, dir, "intellij/mcp.json", `{
		"servers": {
			"my-server": {
				"type": "stdio",
				"command": "my-command",
				"args": ["--flag"],
				"env": {"API_KEY": "secret"}
			},
			"remote": {
				"type": "http",
				"url": "https://mcp.example.com/mcp"
			}
		}
	}`)

	return dir
}

func TestCopilotAppsParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCopilotConfig(t)

	data, err := afs.ReadFile(filepath.Join(dir, "apps.json"))
	require.NoError(t, err)

	var apps map[string]copilotApp
	err = json.Unmarshal(data, &apps)
	require.NoError(t, err)
	assert.Len(t, apps, 2)

	app := apps["github.com:Iv23ctfURkiMfJ4xr5mv"]
	assert.Equal(t, "testuser", app.User)
	assert.Equal(t, "Iv23ctfURkiMfJ4xr5mv", app.GitHubAppID)
	assert.Equal(t, "ghu_test123", app.OAuthToken)
}

func TestCopilotMCPParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCopilotConfig(t)

	path := filepath.Join(dir, "intellij", "mcp.json")
	specs, err := readMcpServersFile(afs, path, "servers")
	require.NoError(t, err)
	require.Len(t, specs, 2)

	server := specs[0]
	assert.Equal(t, "my-server", server.name)
	assert.Equal(t, "stdio", server.transport)
	assert.Equal(t, "my-command", server.command)
	assert.Equal(t, []string{"--flag"}, server.args)
	assert.True(t, server.hasEnv)

	remote := specs[1]
	assert.Equal(t, "remote", remote.name)
	assert.Equal(t, "http", remote.transport)
	assert.Equal(t, "https://mcp.example.com/mcp", remote.url)
	assert.Empty(t, remote.command)

	// The language server's own files keep the historical name-only ids.
	assert.Equal(t, "github.copilot.mcpServer/my-server", copilotMcpServerID(path, "my-server"))
}

func TestGitHubCopilotConfigDir(t *testing.T) {
	assert.Equal(t, filepath.Join("AppData", "Local", "github-copilot"), gitHubCopilotConfigDir("windows"))
	assert.Equal(t, filepath.Join(".config", "github-copilot"), gitHubCopilotConfigDir("darwin"))
	assert.Equal(t, filepath.Join(".config", "github-copilot"), gitHubCopilotConfigDir("linux"))
}

// ~/.copilot/config.json as the Copilot CLI writes it, with leading comments,
// after `copilot plugin install azure@awesome-copilot` and
// `copilot plugin disable azure@awesome-copilot`.
func TestReadCopilotPlugins(t *testing.T) {
	afs := testAfero()
	plugins, err := readCopilotPlugins(afs, aiToolsHome)
	require.NoError(t, err)
	require.Len(t, plugins, 1)

	p := plugins[0]
	assert.Equal(t, "azure", p.Name)
	assert.Equal(t, "awesome-copilot", p.Marketplace)
	assert.Equal(t, "1.2.97", p.Version)
	assert.Equal(t, "azure@awesome-copilot", p.key())
	assert.Equal(t, "/root/.copilot/installed-plugins/awesome-copilot/azure", p.CachePath)
	assert.NotNil(t, parseRFC3339Ptr(p.InstalledAt))

	settings := readCopilotCLISettings(afs, aiToolsHome)
	assert.False(t, settings.pluginEnabled(p))

	none, err := readCopilotPlugins(afs, t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestCopilotPluginEnabled(t *testing.T) {
	on, off := true, false
	p := copilotInstalledPlugin{Name: "azure", Marketplace: "awesome-copilot", Enabled: &on}

	assert.True(t, copilotCLISettings{}.pluginEnabled(p), "the install record decides without settings")
	assert.False(t, copilotCLISettings{EnabledPlugins: map[string]bool{"azure@awesome-copilot": false}}.pluginEnabled(p),
		"settings.json wins over the install record")
	p.Enabled = &off
	assert.False(t, copilotCLISettings{}.pluginEnabled(p))
	p.Enabled = nil
	assert.True(t, copilotCLISettings{}.pluginEnabled(p))
}

func TestCopilotDisabledMcpServers(t *testing.T) {
	settings := copilotCLISettings{DisabledMcpServers: []string{"remote"}}
	assert.True(t, settings.disabled("remote"))
	assert.False(t, settings.disabled("fs"))
}

func TestCopilotMcpServerID(t *testing.T) {
	assert.Equal(t, "github.copilot.mcpServer/fs",
		copilotMcpServerID("/home/alice/.config/github-copilot/mcp.json", "fs"))
	assert.Equal(t, "github.copilot.mcpServer/fs",
		copilotMcpServerID("/home/alice/.config/github-copilot/intellij/mcp.json", "fs"))
	// The CLI's and VS Code's files may both name a server "fs".
	assert.NotEqual(t,
		copilotMcpServerID("/home/alice/.copilot/mcp-config.json", "fs"),
		copilotMcpServerID("/home/alice/.config/Code/User/mcp.json", "fs"))
}
