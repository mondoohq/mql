// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaudeManagedSettingsDir(t *testing.T) {
	// Paths from code.claude.com/docs/en/managed-settings.
	assert.Equal(t, "/Library/Application Support/ClaudeCode/managed-settings.json",
		joinTargetPath("darwin", claudeManagedSettingsDir("darwin"), "managed-settings.json"))
	assert.Equal(t, "/etc/claude-code/managed-settings.json",
		joinTargetPath("debian", claudeManagedSettingsDir("debian"), "managed-settings.json"))
	assert.Equal(t, `C:\Program Files\ClaudeCode\managed-settings.json`,
		joinTargetPath("windows", claudeManagedSettingsDir("windows"), "managed-settings.json"))
}

func TestReadClaudeSettingsHooks(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	// Measured: the user settings.json follows the hooks block of a Claude
	// Code 2.1.312 install on macOS (2026-10-28): one command hook per event,
	// no matcher.
	// Synthetic: the managed file and drop-ins; no target had managed
	// settings. Drop-ins are written out of order, with a hidden file and a
	// non-JSON file that Claude Code ignores.
	writeTestFiles(t, fs, map[string]string{
		"/home/u/.claude/settings.json": `{"model": "opus", "hooks": {
		  "Stop": [{"hooks": [{"type": "command", "command": "/home/u/.config/iterm2/cc-status"}]}],
		  "SessionStart": [{"hooks": [{"type": "command", "command": "/home/u/.config/iterm2/cc-status"}]}]
		}}`,
		"/etc/claude-code/managed-settings.json":                `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/corp/guard.sh", "timeout": 10}]}]}}`,
		"/etc/claude-code/managed-settings.d/20-audit.json":     `{"hooks": {"PostToolUse": [{"hooks": [{"type": "http", "url": "https://audit.example.com/claude"}]}]}}`,
		"/etc/claude-code/managed-settings.d/10-telemetry.json": `{"env": {"OTEL": "1"}}`,
		"/etc/claude-code/managed-settings.d/.hidden.json":      `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "hidden"}]}]}}`,
		"/etc/claude-code/managed-settings.d/README.txt":        `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "readme"}]}]}}`,
	})

	sets, err := readClaudeSettingsHooks(afs, "/home/u/.claude", "debian")
	require.NoError(t, err)
	require.Len(t, sets, 3)

	assert.Equal(t, "/home/u/.claude/settings.json", sets[0].source)
	assert.False(t, sets[0].managed)
	require.Len(t, sets[0].hooks, 2)
	assert.Equal(t, "SessionStart", sets[0].hooks[0].event)
	assert.Equal(t, "Stop", sets[0].hooks[1].event)

	assert.Equal(t, "/etc/claude-code/managed-settings.json", sets[1].source)
	assert.True(t, sets[1].managed)
	assert.Equal(t, "/opt/corp/guard.sh", sets[1].hooks[0].handler.Command)

	assert.Equal(t, "/etc/claude-code/managed-settings.d/20-audit.json", sets[2].source)
	assert.True(t, sets[2].managed)
	assert.Equal(t, "https://audit.example.com/claude", sets[2].hooks[0].handler.URL)
}

func TestReadClaudeSettingsHooksMissing(t *testing.T) {
	// Synthetic: a host with no settings files at all has no hooks.
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	sets, err := readClaudeSettingsHooks(afs, "/home/u/.claude", "darwin")
	require.NoError(t, err)
	assert.Empty(t, sets)
}

func TestReadClaudeSettingsHooksMalformed(t *testing.T) {
	// Synthetic: a hooks block that is a list instead of an event map.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/Library/Application Support/ClaudeCode/managed-settings.json": `{"hooks": [{"matcher": "Bash"}]}`,
	})
	_, err := readClaudeSettingsHooks(&afero.Afero{Fs: fs}, "/Users/u/.claude", "darwin")
	assert.Error(t, err)
}

func TestReadClaudePluginHooks(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	dir := "/home/u/.claude/plugins/cache/official/superpowers/7.0.0"
	// Measured: hooks/hooks.json of the superpowers 7.0.0 plugin
	// (claude-plugins-official, 2026-10-28), with no hooks key in its manifest.
	writeTestFiles(t, fs, map[string]string{
		dir + "/hooks/hooks.json": `{
		  "hooks": {
		    "SessionStart": [
		      {
		        "matcher": "startup|clear|compact",
		        "hooks": [
		          {
		            "type": "command",
		            "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-hook.cmd\" session-start",
		            "shell": "bash",
		            "async": false
		          }
		        ]
		      }
		    ]
		  }
		}`,
	})
	sets := readClaudePluginHooks(afs, dir, nil)
	require.Len(t, sets, 1)
	assert.Equal(t, dir+"/hooks/hooks.json", sets[0].source)
	require.Len(t, sets[0].hooks, 1)
	h := sets[0].hooks[0]
	assert.Equal(t, "SessionStart", h.event)
	assert.Equal(t, "startup|clear|compact", h.matcher)
	assert.Equal(t, "command", h.handler.Type)
	assert.Equal(t, `"${CLAUDE_PLUGIN_ROOT}/hooks/run-hook.cmd" session-start`, h.handler.Command, "the command is returned as written")
}

func TestReadClaudePluginHooksManifest(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	dir := "/plugins/deploy-tools"
	// Synthetic: the manifest forms of code.claude.com/docs/en/plugins-reference,
	// a list mixing a hooks file and an inline event map, plus a second
	// inline map, a path naming the default file again, and an extra file
	// without the "hooks" wrapper, which Claude Code fails to load.
	writeTestFiles(t, fs, map[string]string{
		dir + "/hooks/hooks.json":           `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "default"}]}]}}`,
		dir + "/config/extra-hooks.json":    `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "extra"}]}]}}`,
		dir + "/config/unwrapped.json":      `{"PreToolUse": [{"hooks": [{"type": "command", "command": "unwrapped"}]}]}`,
		dir + "/.claude-plugin/plugin.json": `{}`,
	})
	manifest := json.RawMessage(`[
	  "./config/extra-hooks.json",
	  {"PostToolUse": [{"matcher": "Write|Edit", "hooks": [{"type": "command", "command": "inline-1"}]}]},
	  "./hooks/hooks.json",
	  "./config/unwrapped.json",
	  {"PostToolUse": [{"hooks": [{"type": "command", "command": "inline-2"}]}]}
	]`)
	sets := readClaudePluginHooks(afs, dir, manifest)

	var commands, keys []string
	for _, s := range sets {
		keys = append(keys, s.key)
		for _, h := range s.hooks {
			commands = append(commands, h.handler.Command)
		}
	}
	assert.Equal(t, []string{"default", "extra", "inline-1", "inline-2"}, commands)
	assert.Equal(t, []string{
		dir + "/hooks/hooks.json",
		dir + "/config/extra-hooks.json",
		dir + "/.claude-plugin/plugin.json#1",
		dir + "/.claude-plugin/plugin.json#4",
	}, keys, "inline blocks of one manifest get distinct keys")
	assert.Equal(t, dir+"/.claude-plugin/plugin.json", sets[2].source)

	// Synthetic: a manifest with a single inline map instead of a list.
	sets = readClaudePluginHooks(afs, "/plugins/none", json.RawMessage(`{"Stop": [{"hooks": [{"type": "command", "command": "solo"}]}]}`))
	require.Len(t, sets, 1)
	assert.Equal(t, "solo", sets[0].hooks[0].handler.Command)
}
