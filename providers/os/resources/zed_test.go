// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func createTestZedConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeTestFile(t, dir, "settings.json", `{
		"ui_font_size": 16,
		"buffer_font_size": 16,
		"theme": {
			"mode": "system",
			"light": "One Light",
			"dark": "One Dark"
		},
		"telemetry": {
			"diagnostics": false,
			"metrics": false
		}
	}`)

	mkdirAllTest(t, dir, "extensions/html")
	mkdirAllTest(t, dir, "extensions/toml")

	return dir
}

func TestZedSettingsParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestZedConfig(t)

	var settings map[string]any
	err := readJSONFileAfero(afs, dir, "settings.json", &settings)
	require.NoError(t, err)
	assert.Equal(t, float64(16), settings["ui_font_size"])

	theme := settings["theme"].(map[string]any)
	assert.Equal(t, "system", theme["mode"])

	telemetry := settings["telemetry"].(map[string]any)
	assert.Equal(t, false, telemetry["diagnostics"])
}

func TestZedExtensionsFromDir(t *testing.T) {
	afs := testAfero()
	dir := createTestZedConfig(t)

	entries, err := afs.ReadDir(dir + "/extensions")
	require.NoError(t, err)

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	assert.Contains(t, names, "html")
	assert.Contains(t, names, "toml")
}

func TestZedSettingsJSONC(t *testing.T) {
	dir := t.TempDir()
	// Realistic Zed JSONC: line comments, inline comments, block comments, trailing commas
	writeTestFile(t, dir, "settings.json", `// Zed Settings
//
// For information on how to configure Zed, see the Zed
// documentation: https://zed.dev/docs/configuring-zed
{
  "ui_font_size": 14, // default
  /* Use system theme */
  "theme": {
    "mode": "system",
  }
}`)

	afs := testAfero()
	data, err := afs.ReadFile(dir + "/settings.json")
	require.NoError(t, err)

	clean, err := hujson.Standardize(data)
	require.NoError(t, err)

	var settings map[string]any
	require.NoError(t, json.Unmarshal(clean, &settings))
	assert.Equal(t, float64(14), settings["ui_font_size"])

	theme := settings["theme"].(map[string]any)
	assert.Equal(t, "system", theme["mode"])
}

func TestZedConfigDir(t *testing.T) {
	assert.Equal(t, filepath.Join("AppData", "Roaming", "Zed"), zedConfigDir("windows"))
	assert.Equal(t, filepath.Join(".config", "zed"), zedConfigDir("darwin"))
	assert.Equal(t, filepath.Join(".config", "zed"), zedConfigDir("linux"))
}

func TestZedConfigMissing(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	var settings map[string]any
	err := readJSONFileAfero(afs, dir, "settings.json", &settings)
	assert.Error(t, err)
}

func TestReadZedWorkspacePaths(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.sqlite")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE workspaces (workspace_id INTEGER PRIMARY KEY, local_paths BLOB, window_state TEXT)`)
	require.NoError(t, err)

	// bincode-ish blob: 8-byte length prefix (mostly non-printable) then the path.
	blob := []byte{0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	blob = append(blob, []byte("/pub/go/src/go.mondoo.com/mql")...)
	_, err = db.Exec(`INSERT INTO workspaces (local_paths, window_state) VALUES (?, ?)`, blob, `{"x":1}`)
	require.NoError(t, err)
	// a second workspace whose path is not a printable-leading absolute path
	_, err = db.Exec(`INSERT INTO workspaces (local_paths, window_state) VALUES (?, ?)`, []byte("no-paths-here"), "")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	paths := readZedWorkspacePaths(testAfero(), dbPath)
	assert.Contains(t, paths, "/pub/go/src/go.mondoo.com/mql")

	// missing db yields nil, not a panic
	assert.Nil(t, readZedWorkspacePaths(testAfero(), filepath.Join(dir, "missing.sqlite")))
}

func TestZedSettingsRedactsSecrets(t *testing.T) {
	// Synthetic: a context server whose env carries a database password, in
	// the shape Zed's settings documentation shows for context_servers.
	mockFS := afero.NewMemMapFs()
	writeMemFSFile(t, mockFS, "/home/alice/.config/zed/settings.json", []byte(`{
		// comment
		"ui_font_size": 16,
		"context_servers": {
			"postgres": {"command": {"path": "pg-mcp", "env": {"PGPASSWORD": "hunter2"}}}
		}
	}`))
	r := &mqlZed{
		MqlRuntime: memFSRuntime(t, mockFS),
		ConfigPath: plugin.TValue[string]{Data: "/home/alice/.config/zed", State: plugin.StateIsSet},
	}

	got, err := r.settings()
	require.NoError(t, err)
	settings := got.(map[string]any)
	assert.Equal(t, float64(16), settings["ui_font_size"])
	cmd := settings["context_servers"].(map[string]any)["postgres"].(map[string]any)["command"].(map[string]any)
	assert.Equal(t, "pg-mcp", cmd["path"])
	assert.Equal(t, redactedValue, cmd["env"].(map[string]any)["PGPASSWORD"])
}
