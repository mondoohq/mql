// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadGeminiSettingsHooks(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	// Synthetic: the example of gemini-cli docs/hooks/index.md in a user
	// settings.json with comments, which Gemini CLI accepts, plus a system
	// settings file; no target had Gemini CLI hooks configured.
	writeTestFiles(t, fs, map[string]string{
		"/home/u/.gemini/settings.json": `{
		  // project guard
		  "hooks": {
		    "BeforeTool": [
		      {
		        "matcher": "write_file|replace",
		        "hooks": [
		          {"name": "security-check", "type": "command", "command": "$GEMINI_PROJECT_DIR/.gemini/hooks/security.sh", "timeout": 5000, "description": "Blocks secrets"}
		        ]
		      }
		    ]
		  },
		}`,
		"/etc/gemini-cli/settings.json": `{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "/opt/corp/start.sh"}]}]}}`,
	})

	sets, err := readGeminiSettingsHooks(afs, "/home/u/.gemini", "ubuntu")
	require.NoError(t, err)
	require.Len(t, sets, 2)

	assert.Equal(t, "/home/u/.gemini/settings.json", sets[0].source)
	assert.False(t, sets[0].managed)
	h := sets[0].hooks[0]
	assert.Equal(t, "BeforeTool", h.event)
	assert.Equal(t, "write_file|replace", h.matcher)
	assert.Equal(t, "security-check", h.handler.Name)
	assert.Equal(t, "Blocks secrets", h.handler.Description)
	require.NotNil(t, h.timeout())
	assert.Equal(t, int64(5000), *h.timeout())

	assert.Equal(t, "/etc/gemini-cli/settings.json", sets[1].source)
	assert.True(t, sets[1].managed)
	assert.Equal(t, "/opt/corp/start.sh", sets[1].hooks[0].handler.Command)
}

func TestGeminiSystemSettingsDir(t *testing.T) {
	// Paths from gemini-cli docs/reference/configuration.md.
	assert.Equal(t, "/Library/Application Support/GeminiCli/settings.json",
		joinTargetPath("darwin", geminiSystemSettingsDir("darwin"), "settings.json"))
	assert.Equal(t, `C:\ProgramData\gemini-cli\settings.json`,
		joinTargetPath("windows", geminiSystemSettingsDir("windows"), "settings.json"))
}

func TestReadGeminiSettingsHooksMalformed(t *testing.T) {
	// Synthetic: an event that holds a single group instead of a list.
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/home/u/.gemini/settings.json": `{"hooks": {"BeforeTool": {"hooks": []}}}`,
	})
	_, err := readGeminiSettingsHooks(&afero.Afero{Fs: fs}, "/home/u/.gemini", "ubuntu")
	assert.Error(t, err)

	// Synthetic: no settings files at all.
	sets, err := readGeminiSettingsHooks(&afero.Afero{Fs: afero.NewMemMapFs()}, "/home/u/.gemini", "ubuntu")
	require.NoError(t, err)
	assert.Empty(t, sets)
}

func TestReadGeminiExtensionHooks(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	// Synthetic: an extension hooks file in the wrapped shape gemini-cli's
	// extension manager requires, and one without the wrapper, which it skips.
	writeTestFiles(t, fs, map[string]string{
		"/ext/a/hooks/hooks.json": `{"hooks": {"AfterTool": [{"hooks": [{"type": "command", "command": "${extensionPath}/after.sh"}]}]}}`,
		"/ext/b/hooks/hooks.json": `{"AfterTool": [{"hooks": [{"type": "command", "command": "x"}]}]}`,
	})
	sets := readGeminiExtensionHooks(afs, "/ext/a")
	require.Len(t, sets, 1)
	assert.Equal(t, "${extensionPath}/after.sh", sets[0].hooks[0].handler.Command)

	assert.Empty(t, readGeminiExtensionHooks(afs, "/ext/b"))
	assert.Empty(t, readGeminiExtensionHooks(afs, "/ext/missing"))
	assert.Empty(t, readGeminiExtensionHooks(afs, ""))
}
