// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadCodexHooks(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	// Synthetic: the hooks.json and config.toml forms of the Codex hooks docs
	// (learn.chatgpt.com/docs/hooks); config.toml also carries the
	// [hooks.state] trust table and unrelated keys. No target had Codex hooks.
	writeTestFiles(t, fs, map[string]string{
		"/home/u/.codex/hooks.json": `{
		  "description": "team hooks",
		  "hooks": {
		    "SessionStart": [{"hooks": [{"type": "command", "command": "python3 ~/.codex/hooks/session_start.py", "statusMessage": "starting"}]}]
		  }
		}`,
		"/home/u/.codex/config.toml": `
model = "gpt-5.3-codex"

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/bin/python3 /opt/hooks/pre_tool.py"
timeout = 30

[[hooks.PreToolUse.hooks]]
type = "mcp_tool"
server = "guard"
tool = "scan"

[hooks.state."user:PreToolUse:0:0"]
enabled = true
trusted_hash = "abc"
`,
	})

	sets, err := readCodexHooks(afs, "/home/u/.codex")
	require.NoError(t, err)
	require.Len(t, sets, 2)

	assert.Equal(t, "/home/u/.codex/hooks.json", sets[0].source)
	require.Len(t, sets[0].hooks, 1)
	assert.Equal(t, "SessionStart", sets[0].hooks[0].event)
	assert.Equal(t, "", sets[0].hooks[0].matcher)

	assert.Equal(t, "/home/u/.codex/config.toml", sets[1].source)
	require.Len(t, sets[1].hooks, 2, "the state table is not an event")
	h := sets[1].hooks[0]
	assert.Equal(t, "PreToolUse", h.event)
	assert.Equal(t, "^Bash$", h.matcher)
	assert.Equal(t, "/usr/bin/python3 /opt/hooks/pre_tool.py", h.handler.Command)
	require.NotNil(t, h.timeout())
	assert.Equal(t, int64(30), *h.timeout())
	assert.Equal(t, "mcp_tool", sets[1].hooks[1].handler.Type)
	assert.Equal(t, 1, sets[1].hooks[1].index)
}

func TestReadCodexHooksMissingAndMalformed(t *testing.T) {
	// Synthetic: no configuration files.
	sets, err := readCodexHooks(&afero.Afero{Fs: afero.NewMemMapFs()}, "/home/u/.codex")
	require.NoError(t, err)
	assert.Empty(t, sets)

	// Synthetic: a config.toml without hooks.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{"/home/u/.codex/config.toml": `model = "o3"`})
	sets, err = readCodexHooks(&afero.Afero{Fs: fs}, "/home/u/.codex")
	require.NoError(t, err)
	assert.Empty(t, sets)

	// Synthetic: an event written as a single table instead of an array of
	// tables, and a hooks.json whose event is not a list.
	fs = afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{"/home/u/.codex/config.toml": "[hooks.Stop]\nmatcher = \"x\"\n"})
	_, err = readCodexHooks(&afero.Afero{Fs: fs}, "/home/u/.codex")
	assert.Error(t, err)

	fs = afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{"/home/u/.codex/hooks.json": `{"hooks": {"Stop": "echo"}}`})
	_, err = readCodexHooks(&afero.Afero{Fs: fs}, "/home/u/.codex")
	assert.Error(t, err)
}
