// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCodexConfig creates a temporary directory tree mimicking an OpenAI Codex
// config directory and returns its path.
func createTestCodexConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// auth.json
	writeTestFile(t, dir, "auth.json", `{
		"auth_mode": "chatgpt",
		"tokens": {
			"account_id": "test-account-uuid"
		},
		"last_refresh": "2026-04-01T12:00:00Z"
	}`)

	// Plugin: github (with .codex-plugin/plugin.json, .app.json, skills)
	githubPluginDir := filepath.Join(".tmp", "plugins", "plugins", "github")
	mkdirAllTest(t, dir, filepath.Join(githubPluginDir, ".codex-plugin"))
	mkdirAllTest(t, dir, filepath.Join(githubPluginDir, "skills", "gh-fix-ci"))
	mkdirAllTest(t, dir, filepath.Join(githubPluginDir, "skills", "github"))

	writeTestFile(t, dir, filepath.Join(githubPluginDir, ".codex-plugin", "plugin.json"), `{
		"name": "github",
		"version": "0.1.0",
		"description": "Inspect repositories, triage pull requests and issues.",
		"author": {"name": "OpenAI"},
		"interface": {
			"category": "Coding",
			"capabilities": ["Interactive", "Write"]
		}
	}`)
	writeTestFile(t, dir, filepath.Join(githubPluginDir, ".app.json"), `{
		"apps": {
			"github": {"id": "connector_abc123"}
		}
	}`)
	writeTestFile(t, dir, filepath.Join(githubPluginDir, "skills", "github", "SKILL.md"), `---
name: github
description: General GitHub triage and orientation.
---

# GitHub
`)
	writeTestFile(t, dir, filepath.Join(githubPluginDir, "skills", "gh-fix-ci", "SKILL.md"), `---
name: gh-fix-ci
description: Debug and fix failing CI checks.
---

# Fix CI
`)

	// Plugin: cloudflare (with .mcp.json, hooks.json)
	cfPluginDir := filepath.Join(".tmp", "plugins", "plugins", "cloudflare")
	mkdirAllTest(t, dir, filepath.Join(cfPluginDir, ".codex-plugin"))

	writeTestFile(t, dir, filepath.Join(cfPluginDir, ".codex-plugin", "plugin.json"), `{
		"name": "cloudflare",
		"version": "0.2.0",
		"description": "Edge computing platform.",
		"author": {"name": "OpenAI"},
		"interface": {
			"category": "Coding",
			"capabilities": ["Read"]
		}
	}`)
	writeTestFile(t, dir, filepath.Join(cfPluginDir, ".mcp.json"), `{
		"mcpServers": {
			"cloudflare-api": {
				"type": "http",
				"url": "https://mcp.cloudflare.com/mcp",
				"note": "Official Cloudflare API MCP server."
			},
			"local-fs": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {"FS_TOKEN": "secret"}
			}
		}
	}`)
	writeTestFile(t, dir, filepath.Join(cfPluginDir, "hooks.json"), `{
		"hooks": {"PostToolUse": []}
	}`)

	// Plugin: slack (minimal, with .app.json only)
	slackPluginDir := filepath.Join(".tmp", "plugins", "plugins", "slack")
	mkdirAllTest(t, dir, slackPluginDir)
	writeTestFile(t, dir, filepath.Join(slackPluginDir, ".app.json"), `{
		"apps": {
			"slack": {"id": "asdk_app_slack123"}
		}
	}`)

	// System skill
	mkdirAllTest(t, dir, filepath.Join("skills", ".system", "imagegen"))
	writeTestFile(t, dir, filepath.Join("skills", ".system", "imagegen", "SKILL.md"), `---
name: imagegen
description: Generate or edit raster images.
---

# Image Generation
`)

	return dir
}

func TestCodexAuthParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)

	var auth codexAuthJSON
	err := readJSONFileAfero(afs, dir, "auth.json", &auth)
	require.NoError(t, err)
	assert.Equal(t, "chatgpt", auth.AuthMode)
	assert.Equal(t, "2026-04-01T12:00:00Z", auth.LastRefresh)
	require.NotNil(t, auth.Tokens)
	assert.Equal(t, "test-account-uuid", auth.Tokens.AccountID)
}

func TestCodexPluginParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)
	pluginDir := filepath.Join(dir, ".tmp", "plugins", "plugins", "github")

	var pj codexPluginJSON
	err := readJSONFileAfero(afs, pluginDir, ".codex-plugin/plugin.json", &pj)
	require.NoError(t, err)
	assert.Equal(t, "0.1.0", pj.Version)
	assert.Equal(t, "Inspect repositories, triage pull requests and issues.", pj.Description)
	require.NotNil(t, pj.Author)
	assert.Equal(t, "OpenAI", pj.Author.Name)
	require.NotNil(t, pj.Interface)
	assert.Equal(t, "Coding", pj.Interface.Category)
	assert.Equal(t, []string{"Interactive", "Write"}, pj.Interface.Capabilities)
}

func TestCodexMcpServerParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)
	cfDir := filepath.Join(dir, ".tmp", "plugins", "plugins", "cloudflare")

	data, err := afs.ReadFile(filepath.Join(cfDir, ".mcp.json"))
	require.NoError(t, err)

	var mcpConfig struct {
		McpServers map[string]codexMcpServerEntry `json:"mcpServers"`
	}
	require.NoError(t, json.Unmarshal(data, &mcpConfig))
	require.Contains(t, mcpConfig.McpServers, "cloudflare-api")

	srv := mcpConfig.McpServers["cloudflare-api"]
	assert.Equal(t, "http", srv.Type)
	assert.Equal(t, "https://mcp.cloudflare.com/mcp", srv.URL)
	assert.Equal(t, "Official Cloudflare API MCP server.", srv.Note)

	// stdio server: command/args/env are now captured too
	local := mcpConfig.McpServers["local-fs"]
	assert.Equal(t, "npx", local.Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, local.Args)
	assert.NotEmpty(t, local.Env)
	assert.Equal(t, mcpTransportStdio, deriveMcpTransport(local.Type, local.Command, local.URL))
}

func TestCodexConnectorParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)
	githubDir := filepath.Join(dir, ".tmp", "plugins", "plugins", "github")

	var appConfig struct {
		Apps map[string]struct {
			ID string `json:"id"`
		} `json:"apps"`
	}
	err := readJSONFileAfero(afs, githubDir, ".app.json", &appConfig)
	require.NoError(t, err)
	require.Contains(t, appConfig.Apps, "github")
	assert.Equal(t, "connector_abc123", appConfig.Apps["github"].ID)
}

func TestCodexPluginDiscovery(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)
	pluginsDir := filepath.Join(dir, ".tmp", "plugins", "plugins")

	entries, err := afs.ReadDir(pluginsDir)
	require.NoError(t, err)

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	assert.Contains(t, names, "github")
	assert.Contains(t, names, "cloudflare")
	assert.Contains(t, names, "slack")
}

func TestCodexPluginHasMcpAndHooks(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)
	cfDir := filepath.Join(dir, ".tmp", "plugins", "plugins", "cloudflare")
	githubDir := filepath.Join(dir, ".tmp", "plugins", "plugins", "github")

	exists, _ := afs.Exists(filepath.Join(cfDir, ".mcp.json"))
	assert.True(t, exists, "cloudflare should have .mcp.json")

	exists, _ = afs.Exists(filepath.Join(cfDir, "hooks.json"))
	assert.True(t, exists, "cloudflare should have hooks.json")

	exists, _ = afs.Exists(filepath.Join(githubDir, ".mcp.json"))
	assert.False(t, exists, "github should not have .mcp.json")

	exists, _ = afs.Exists(filepath.Join(githubDir, "hooks.json"))
	assert.False(t, exists, "github should not have hooks.json")
}

func TestCodexSkillDiscovery(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)

	// System skills
	systemDir := filepath.Join(dir, "skills", ".system")
	entries, err := afs.ReadDir(systemDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "imagegen", entries[0].Name())

	// Plugin skills
	githubSkillsDir := filepath.Join(dir, ".tmp", "plugins", "plugins", "github", "skills")
	skillEntries, err := afs.ReadDir(githubSkillsDir)
	require.NoError(t, err)

	var skillNames []string
	for _, e := range skillEntries {
		if e.IsDir() {
			skillNames = append(skillNames, e.Name())
		}
	}
	assert.Contains(t, skillNames, "github")
	assert.Contains(t, skillNames, "gh-fix-ci")
}

func TestCodexSkillParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)

	skillPath := filepath.Join(dir, ".tmp", "plugins", "plugins", "github", "skills", "github", "SKILL.md")
	data, err := afs.ReadFile(skillPath)
	require.NoError(t, err)

	skill := parseSkillMd("github", skillPath, string(data))
	assert.Equal(t, "github", skill.name)
	assert.Equal(t, "General GitHub triage and orientation.", skill.description)
	assert.Equal(t, skillPath, skill.source)
}

func TestCodexConfigIntegration(t *testing.T) {
	afs := testAfero()
	dir := createTestCodexConfig(t)

	// Auth
	var auth codexAuthJSON
	require.NoError(t, readJSONFileAfero(afs, dir, "auth.json", &auth))
	assert.Equal(t, "chatgpt", auth.AuthMode)
	assert.Equal(t, "test-account-uuid", auth.Tokens.AccountID)

	// Plugins with metadata
	pluginsDir := filepath.Join(dir, ".tmp", "plugins", "plugins")

	// github plugin
	var ghPlugin codexPluginJSON
	require.NoError(t, readJSONFileAfero(afs, filepath.Join(pluginsDir, "github"), ".codex-plugin/plugin.json", &ghPlugin))
	assert.Equal(t, "0.1.0", ghPlugin.Version)

	// cloudflare plugin has MCP
	var mcpConfig struct {
		McpServers map[string]codexMcpServerEntry `json:"mcpServers"`
	}
	mcpData, err := afs.ReadFile(filepath.Join(pluginsDir, "cloudflare", ".mcp.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(mcpData, &mcpConfig))
	assert.Len(t, mcpConfig.McpServers, 2)

	// Connectors from github and slack
	var ghApp struct {
		Apps map[string]struct {
			ID string `json:"id"`
		} `json:"apps"`
	}
	require.NoError(t, readJSONFileAfero(afs, filepath.Join(pluginsDir, "github"), ".app.json", &ghApp))
	assert.Equal(t, "connector_abc123", ghApp.Apps["github"].ID)

	var slackApp struct {
		Apps map[string]struct {
			ID string `json:"id"`
		} `json:"apps"`
	}
	require.NoError(t, readJSONFileAfero(afs, filepath.Join(pluginsDir, "slack"), ".app.json", &slackApp))
	assert.Equal(t, "asdk_app_slack123", slackApp.Apps["slack"].ID)

	// System skill
	skillData, err := afs.ReadFile(filepath.Join(dir, "skills", ".system", "imagegen", "SKILL.md"))
	require.NoError(t, err)
	skill := parseSkillMd("imagegen", "imagegen/SKILL.md", string(skillData))
	assert.Equal(t, "imagegen", skill.name)
	assert.Equal(t, "Generate or edit raster images.", skill.description)
}

func TestCodexSessionCwd(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	// valid session_meta first line, followed by other records
	writeTestFile(t, dir, "rollout-valid.jsonl",
		`{"timestamp":"2026-05-05T09:13:01Z","type":"session_meta","payload":{"id":"abc","cwd":"/pub/go/src/go.mondoo.com/mql","cli_version":"0.128.0"}}`+"\n"+
			`{"type":"message","payload":{"role":"user"}}`+"\n")
	assert.Equal(t, "/pub/go/src/go.mondoo.com/mql", codexSessionCwd(afs, filepath.Join(dir, "rollout-valid.jsonl")))

	// first record is not session_meta -> empty
	writeTestFile(t, dir, "rollout-nometa.jsonl", `{"type":"message","payload":{"cwd":"/should/not/read"}}`+"\n")
	assert.Equal(t, "", codexSessionCwd(afs, filepath.Join(dir, "rollout-nometa.jsonl")))

	// missing file -> empty
	assert.Equal(t, "", codexSessionCwd(afs, filepath.Join(dir, "missing.jsonl")))
}

// Codex configures MCP servers as `[mcp_servers.<name>]` tables in config.toml.
// Layout as Codex writes it on Windows, including a literal-string project key.
func TestCodexConfigMcpServers(t *testing.T) {
	var cfg codexConfig
	_, err := toml.Decode(`model = "gpt-5-codex"
model_provider = "openai"
[projects.'C:\Users\alice\src\api-backend']
trust_level = "trusted"
[mcp_servers.memory]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-memory"]
[mcp_servers.sequential-thinking]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-sequential-thinking"]
env = { DEBUG = "1" }
[mcp_servers.docs]
url = "https://mcp.example.com/mcp"
`, &cfg)
	require.NoError(t, err)

	assert.Equal(t, "gpt-5-codex", cfg.Model)
	require.Len(t, cfg.McpServers, 3)
	assert.Equal(t, "npx", cfg.McpServers["memory"].Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-memory"}, cfg.McpServers["memory"].Args)
	assert.Empty(t, cfg.McpServers["memory"].Env)
	assert.Equal(t, map[string]string{"DEBUG": "1"}, cfg.McpServers["sequential-thinking"].Env)
	assert.Equal(t, "https://mcp.example.com/mcp", cfg.McpServers["docs"].URL)
	assert.Equal(t, mcpTransportHTTP, deriveMcpTransport("", cfg.McpServers["docs"].Command, cfg.McpServers["docs"].URL))
}
