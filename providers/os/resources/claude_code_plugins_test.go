// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// installedPluginsTemplate follows the shape of a real
// plugins/installed_plugins.json: one plugin installed for the user and
// again for two projects, another installed for the user only.
const installedPluginsTemplate = `{
  "version": 2,
  "plugins": {
    "frontend-design@claude-plugins-official": [
      {"scope": "project", "projectPath": "{{B}}", "installPath": "{{CACHE}}/frontend-design/e18ff5086423", "version": "e18ff5086423", "installedAt": "2026-08-01T10:00:00.000Z", "lastUpdated": "2026-08-01T10:00:00.000Z", "gitCommitSha": "e18ff5086423"},
      {"scope": "user", "installPath": "{{CACHE}}/frontend-design/465f09344424", "version": "465f09344424", "installedAt": "2026-07-01T10:00:00.000Z", "lastUpdated": "2026-07-01T10:00:00.000Z", "gitCommitSha": "465f09344424"},
      {"scope": "project", "projectPath": "{{A}}", "installPath": "{{CACHE}}/frontend-design/0120fb83da5d", "version": "0120fb83da5d", "installedAt": "2026-09-01T10:00:00.000Z", "lastUpdated": "2026-09-01T10:00:00.000Z", "gitCommitSha": "0120fb83da5d"}
    ],
    "vercel@claude-plugins-official": [
      {"scope": "user", "installPath": "{{CACHE}}/vercel/0.50.0", "version": "0.50.0", "installedAt": "2026-10-01T10:00:00.000Z", "lastUpdated": "2026-10-01T10:00:00.000Z"}
    ]
  }
}`

func writeClaudePluginRecordsFixture(t *testing.T) (configDir, projectA, projectB string) {
	t.Helper()
	root := t.TempDir()
	configDir = filepath.Join(root, ".claude")
	projectA = filepath.Join(root, "dev", "a")
	projectB = filepath.Join(root, "dev", "b")
	for _, d := range []string{filepath.Join(configDir, "plugins"), filepath.Join(projectA, ".claude"), filepath.Join(projectB, ".claude")} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}

	r := strings.NewReplacer("{{A}}", projectA, "{{B}}", projectB, "{{CACHE}}", filepath.Join(configDir, "plugins", "cache"))
	writeTestFile(t, configDir, filepath.Join("plugins", "installed_plugins.json"), r.Replace(installedPluginsTemplate))

	// The user enables frontend-design and disables vercel. Project A turns
	// frontend-design off in its local settings, project B in its shared
	// settings only to have its local settings turn it back on.
	writeTestFile(t, configDir, "settings.json", `{"enabledPlugins":{"frontend-design@claude-plugins-official":true,"vercel@claude-plugins-official":false}}`)
	writeTestFile(t, projectA, ".claude/settings.local.json", `{"enabledPlugins":{"frontend-design@claude-plugins-official":false}}`)
	writeTestFile(t, projectB, ".claude/settings.json", `{"enabledPlugins":{"frontend-design@claude-plugins-official":false}}`)
	writeTestFile(t, projectB, ".claude/settings.local.json", `{"enabledPlugins":{"frontend-design@claude-plugins-official":true}}`)
	return configDir, projectA, projectB
}

func TestReadClaudePluginRecords(t *testing.T) {
	configDir, projectA, projectB := writeClaudePluginRecordsFixture(t)

	records, err := readClaudePluginRecords(testAfero(), configDir)
	require.NoError(t, err)
	require.Len(t, records, 4)

	// Sorted by name, then user before project installs, then by project.
	assert.Equal(t, "user", records[0].entry.Scope)
	assert.Equal(t, projectA, records[1].entry.ProjectPath)
	assert.Equal(t, projectB, records[2].entry.ProjectPath)
	assert.Equal(t, "vercel@claude-plugins-official", records[3].name)

	assert.True(t, records[0].enabled, "user settings enable it")
	assert.False(t, records[1].enabled, "project A's settings.local.json overrides the user")
	assert.True(t, records[2].enabled, "project B's settings.local.json overrides its settings.json")
	assert.False(t, records[3].enabled, "user settings disable it")
}

func TestReadClaudePluginRecordsMissing(t *testing.T) {
	records, err := readClaudePluginRecords(testAfero(), t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, records)
}

// Every project install of a plugin needs its own id, or the resource cache
// reports the first install for all of them.
func TestClaudePluginIDPerProject(t *testing.T) {
	assert.Equal(t, "claude.code.plugin/frontend-design@claude-plugins-official/user",
		claudePluginID("frontend-design@claude-plugins-official", "user", ""))
	assert.NotEqual(t,
		claudePluginID("frontend-design@claude-plugins-official", "project", "/home/alice/dev/a"),
		claudePluginID("frontend-design@claude-plugins-official", "project", "/home/alice/dev/b"))
}

func TestClaudePluginMarketplace(t *testing.T) {
	assert.Equal(t, "claude-plugins-official", claudePluginMarketplace("vercel@claude-plugins-official"))
	assert.Empty(t, claudePluginMarketplace("local-plugin"))
}

// known_marketplaces.json as Claude Code writes it.
func TestReadClaudeMarketplaces(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "plugins"), 0o755))
	data, err := os.ReadFile(filepath.Join(claudePluginsTestdata, "known_marketplaces.json"))
	require.NoError(t, err)
	writeTestFile(t, dir, filepath.Join("plugins", "known_marketplaces.json"), string(data))

	markets, err := readClaudeMarketplaces(testAfero(), dir)
	require.NoError(t, err)
	require.Contains(t, markets, "claude-plugins-official")
	official := markets["claude-plugins-official"]
	assert.Equal(t, "github", official.Source.Source)
	assert.Equal(t, "anthropics/claude-plugins-official", official.Source.Repo)
	assert.Equal(t, "/Users/alice/.claude/plugins/marketplaces/claude-plugins-official", official.InstallLocation)
	ts := parseRFC3339Ptr(official.LastUpdated)
	require.NotNil(t, ts)
	assert.True(t, ts.After(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))

	none, err := readClaudeMarketplaces(testAfero(), t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, none)
}
