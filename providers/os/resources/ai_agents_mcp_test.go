// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// config.toml written by `vibe mcp add`: a stdio server with an env table
// and a remote server whose header sits in auth.headers.
func TestParseVibeMcpServers(t *testing.T) {
	path := filepath.Join(aiToolsHome, ".vibe", "config.toml")
	data, err := testAfero().ReadFile(path)
	require.NoError(t, err)

	specs, err := parseVibeMcpServers(data, path)
	require.NoError(t, err)
	assertFsAndRemote(t, specs, true)
	assert.Equal(t, path, specs[0].source)
	assert.True(t, specs[0].enabled)
}

func TestParseVibeMcpServersHeaderForms(t *testing.T) {
	specs, err := parseVibeMcpServers([]byte(`
[[mcp_servers]]
name = "plain"
url = "https://a.example.com/mcp"
transport = "streamable-http"
headers = { "X-Api-Key" = "k" }

[[mcp_servers]]
name = "keyenv"
url = "https://b.example.com/mcp"
api_key_env = "B_TOKEN"

[[mcp_servers]]
name = "off"
command = "srv"
disabled = true
`), "config.toml")
	require.NoError(t, err)
	byName := mcpSpecsByName(specs)
	assert.True(t, byName["plain"].hasHeaders)
	assert.Equal(t, mcpTransportHTTP, byName["plain"].transport)
	assert.True(t, byName["keyenv"].hasHeaders)
	assert.False(t, byName["off"].enabled)

	_, err = parseVibeMcpServers([]byte(`[[mcp_servers]`), "config.toml")
	assert.Error(t, err)
}

// `opencode plugin` writes the plugin list into opencode.jsonc; `kilo plugin`
// writes it into ~/.config/kilo/opencode.json while `kilo mcp add` writes
// kilo.jsonc.
func TestReadOpencodePlugins(t *testing.T) {
	afs := testAfero()

	plugins, err := readOpencodePlugins(afs, opencodeConfigFiles(filepath.Join(aiToolsHome, ".config", "opencode")))
	require.NoError(t, err)
	assert.Equal(t, []string{"opencode-wakatime"}, plugins)

	files := kiloConfigFiles(aiToolsHome)
	plugins, err = readOpencodePlugins(afs, append(files, files...))
	require.NoError(t, err)
	assert.Equal(t, []string{"opencode-wakatime"}, plugins, "duplicates across files are reported once")

	specs, err := readMcpServersFiles(afs, files, "mcp")
	require.NoError(t, err)
	assertFsAndRemote(t, specs, true)
	assert.Equal(t, filepath.Join(aiToolsHome, ".config", "kilo", "kilo.jsonc"), specs[0].source)
}

func TestReadMcpServersFilesMalformed(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "opencode.json", `{"mcp": {`)
	_, err := readMcpServersFiles(testAfero(), opencodeConfigFiles(dir), "mcp")
	assert.Error(t, err)
}
