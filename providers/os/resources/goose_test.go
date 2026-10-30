// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func createTestGooseConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeTestFile(t, dir, "config.yaml", `extensions:
  developer:
    enabled: true
    type: builtin
    name: developer
    description: General development tools useful for software engineering.
    timeout: 300
    bundled: true
  memory:
    enabled: false
    type: builtin
    name: memory
    description: Teach goose your preferences as you go.
    timeout: 300
    bundled: true
  skills:
    enabled: true
    type: platform
    name: skills
    description: Load and use skills from relevant directories
    bundled: true
GOOSE_TELEMETRY_ENABLED: false
GOOSE_PROVIDER: custom_ollama
GOOSE_MODEL: qwen3:8b
`)

	return dir
}

func TestGooseConfigParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestGooseConfig(t)

	data, err := afs.ReadFile(dir + "/config.yaml")
	require.NoError(t, err)

	var config gooseConfig
	err = yaml.Unmarshal(data, &config)
	require.NoError(t, err)

	assert.Equal(t, "custom_ollama", config.Provider)
	assert.Equal(t, "qwen3:8b", config.Model)
	require.NotNil(t, config.TelemetryEnabled)
	assert.False(t, *config.TelemetryEnabled)
	assert.False(t, gooseTelemetryEnabled(&config))
	assert.Len(t, config.Extensions, 3)

	dev := config.Extensions["developer"]
	assert.True(t, dev.Enabled)
	assert.Equal(t, "builtin", dev.Type)
	assert.Equal(t, "developer", dev.Name)
	assert.Equal(t, 300, dev.Timeout)
	assert.True(t, dev.Bundled)

	mem := config.Extensions["memory"]
	assert.False(t, mem.Enabled)

	skills := config.Extensions["skills"]
	assert.True(t, skills.Enabled)
	assert.Equal(t, "platform", skills.Type)
}

// Goose's telemetry is opt-in: a configuration without the key reads as off,
// and only an explicit true turns it on.
func TestGooseTelemetryEnabled(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want bool
	}{
		"absent":   {yaml: "GOOSE_PROVIDER: anthropic\n", want: false},
		"enabled":  {yaml: "GOOSE_TELEMETRY_ENABLED: true\n", want: true},
		"disabled": {yaml: "GOOSE_TELEMETRY_ENABLED: false\n", want: false},
	} {
		t.Run(name, func(t *testing.T) {
			var config gooseConfig
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &config))
			assert.Equal(t, tc.want, gooseTelemetryEnabled(&config))
		})
	}
	var config gooseConfig
	require.NoError(t, yaml.Unmarshal([]byte("GOOSE_PROVIDER: anthropic\n"), &config))
	assert.Nil(t, config.TelemetryEnabled)
}

func TestGooseConfigDir(t *testing.T) {
	assert.Equal(t, filepath.Join("AppData", "Roaming", "Block", "goose", "config"), gooseConfigDir("windows"))
	assert.Equal(t, filepath.Join(".config", "goose"), gooseConfigDir("darwin"))
	assert.Equal(t, filepath.Join(".config", "goose"), gooseConfigDir("linux"))
	assert.Equal(t, filepath.Join(".config", "goose"), gooseConfigDir(""))
}

// config.yaml written by `goose configure` after adding a command-line
// extension "fs" (with an environment variable, whose value goes to the
// secret store) and a remote extension "remote" (with a header), next to the
// platform extensions Goose ships.
func loadGooseTestdataConfig(t *testing.T) *gooseConfig {
	t.Helper()
	data, err := testAfero().ReadFile(filepath.Join(aiToolsHome, ".config", "goose", "config.yaml"))
	require.NoError(t, err)
	var config gooseConfig
	require.NoError(t, yaml.Unmarshal(data, &config))
	return &config
}

func TestGooseMcpServersFromConfigure(t *testing.T) {
	config := loadGooseTestdataConfig(t)
	specs := gooseMcpServers(config, "config.yaml")
	require.Len(t, specs, 2, "platform extensions are not MCP servers")

	fs := specs[0]
	assert.Equal(t, "fs", fs.name)
	assert.Equal(t, mcpTransportStdio, fs.transport)
	assert.Equal(t, "npx", fs.command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, fs.args)
	assert.True(t, fs.hasEnv, "env_keys names the variable kept in the secret store")
	assert.False(t, fs.hasHeaders)
	assert.True(t, fs.enabled)

	remote := specs[1]
	assert.Equal(t, "remote", remote.name)
	assert.Equal(t, mcpTransportHTTP, remote.transport, "streamable_http")
	assert.Equal(t, "https://mcp.example.com/mcp", remote.url)
	assert.True(t, remote.hasHeaders)
	assert.False(t, remote.hasEnv)
}

// `goose configure` replaces GOOSE_PROVIDER and GOOSE_MODEL with
// active_provider and the provider's entry under providers.
func TestGooseActiveProviderAndModel(t *testing.T) {
	config := loadGooseTestdataConfig(t)
	assert.Empty(t, config.Provider)
	assert.Equal(t, "openai", config.activeProvider())
	assert.Equal(t, "gpt-4o", config.activeModel())

	legacy := &gooseConfig{Provider: "anthropic", Model: "claude-sonnet", ActiveProvider: "openai"}
	assert.Equal(t, "anthropic", legacy.activeProvider(), "GOOSE_PROVIDER wins when set")
	assert.Equal(t, "claude-sonnet", legacy.activeModel())

	assert.Empty(t, (&gooseConfig{}).activeModel())
}
