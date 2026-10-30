// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The gemini-cli-security extension in testdata was installed with
// `gemini extensions install` and `qwen extensions install`, then disabled for
// the user in Gemini (extension-enablement.json: "!/root/*") and left enabled
// in Qwen.
func TestReadGeminiExtensions(t *testing.T) {
	afs := testAfero()
	configDir := filepath.Join(aiToolsHome, ".gemini")
	exts, err := readGeminiExtensions(afs, configDir, geminiFlavor, func(string) bool { return true })
	require.NoError(t, err)
	require.Len(t, exts, 1)

	e := exts[0]
	dir := filepath.Join(configDir, "extensions", "gemini-cli-security")
	assert.Equal(t, "gemini-cli-security", e.name)
	assert.Equal(t, "0.5.0", e.version)
	assert.Equal(t, dir, e.dir)
	assert.Equal(t, "https://github.com/gemini-cli-extensions/security", e.source)
	assert.Equal(t, "github-release", e.installType)
	assert.Equal(t, "v0.5.0", e.releaseTag)
	assert.Equal(t, "GEMINI.md", e.contextFileName)
	assert.Equal(t, []string{"security:analyze", "security:analyze-github-pr"}, e.commands)
	assert.Equal(t, filepath.Join(dir, "skills"), e.skillsDir)

	byName := mcpSpecsByName(e.mcpServers)
	require.Len(t, byName, 2)
	assert.Equal(t, "node", byName["securityServer"].command)
	assert.Equal(t, []string{dir + "/mcp-server/dist/index.js"}, byName["securityServer"].args, "${extensionPath} is expanded")
	assert.Equal(t, dir+"/osv-scanner", byName["osvScanner"].command)
	assert.Equal(t, filepath.Join(dir, "gemini-extension.json"), byName["osvScanner"].source)
}

func TestReadGeminiExtensionsQwenManifest(t *testing.T) {
	configDir := filepath.Join(aiToolsHome, ".qwen")
	exts, err := readGeminiExtensions(testAfero(), configDir, qwenFlavor, func(string) bool { return true })
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.Equal(t, "github-release", exts[0].installType)
	assert.Equal(t, filepath.Join(configDir, "extensions", "gemini-cli-security", "qwen-extension.json"),
		exts[0].mcpServers[0].source, "qwen-extension.json is preferred")
}

func TestReadGeminiExtensionsMissing(t *testing.T) {
	exts, err := readGeminiExtensions(testAfero(), t.TempDir(), geminiFlavor, func(string) bool { return true })
	require.NoError(t, err)
	assert.Empty(t, exts)
}

func TestExtensionEnabledFor(t *testing.T) {
	home := "/root"
	assert.True(t, extensionEnabledFor(nil, home, true), "no rules keep the default")
	assert.False(t, extensionEnabledFor(nil, home, false))
	assert.False(t, extensionEnabledFor([]string{"!/root/*"}, home, true))
	assert.True(t, extensionEnabledFor([]string{"/root/*"}, home, false))
	assert.True(t, extensionEnabledFor([]string{"!/root/*", "/root/*"}, home, true), "the last matching rule wins")
	assert.True(t, extensionEnabledFor([]string{"!/home/bob/*"}, home, true), "another user's rule does not match")
	assert.False(t, extensionEnabledFor([]string{"!/"}, "/", true))
	assert.True(t, extensionEnabledFor([]string{"!/root/project/"}, home, true), "a workspace rule does not match the home")
}

// The enablement rules name the home they were written in (/root), so the
// testdata files are mounted there.
func TestGeminiAndQwenEnablementFromTestdata(t *testing.T) {
	fs := afero.NewMemMapFs()
	for _, rel := range []string{
		".gemini/extensions/extension-enablement.json",
		".qwen/extensions/extension-enablement.json",
		".qwen/extension-store/state.json",
	} {
		data, err := testAfero().ReadFile(filepath.Join(aiToolsHome, rel))
		require.NoError(t, err)
		require.NoError(t, afero.WriteFile(fs, "/root/"+rel, data, 0o644))
	}
	afs := &afero.Afero{Fs: fs}

	gemini := geminiExtensionEnabled(afs, "/root/.gemini")
	assert.False(t, gemini("gemini-cli-security"), "disabled for the user: !/root/*")
	assert.True(t, gemini("not-configured"))

	qwen := qwenExtensionEnabled(afs, "/root/.qwen")
	assert.True(t, qwen("gemini-cli-security"), "re-enabled after a disable: /root/* last")

	// The same rules do not apply to another user's home.
	assert.True(t, geminiExtensionEnabled(afs, "/home/alice/.gemini")("gemini-cli-security"))
}

// Qwen keeps a default activation per extension in its extension store.
func TestQwenExtensionDefaultActivation(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/home/alice/.qwen/extension-store/state.json": `{"extensions":{"abc":{"name":"off","defaultActivation":"disabled"},"def":{"name":"ruled","defaultActivation":"enabled","legacyPathRules":["!/home/alice/*"]}}}`,
	})
	enabled := qwenExtensionEnabled(&afero.Afero{Fs: fs}, "/home/alice/.qwen")
	assert.False(t, enabled("off"))
	assert.False(t, enabled("ruled"))
	assert.True(t, enabled("unknown"))
}

// Two store entries with one name are visited in key order, so the answer
// does not depend on map iteration: the last key's activation applies.
func TestQwenExtensionDuplicateNameIsStable(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFiles(t, fs, map[string]string{
		"/home/alice/.qwen/extension-store/state.json": `{"extensions":{"aaa":{"name":"dup","defaultActivation":"enabled"},"bbb":{"name":"dup","defaultActivation":"disabled"}}}`,
	})
	for range 50 {
		enabled := qwenExtensionEnabled(&afero.Afero{Fs: fs}, "/home/alice/.qwen")
		require.False(t, enabled("dup"))
	}
}

func TestGeminiContextFileName(t *testing.T) {
	assert.Equal(t, "GEMINI.md", geminiContextFileName(json.RawMessage(`"GEMINI.md"`)))
	assert.Equal(t, "A.md,B.md", geminiContextFileName(json.RawMessage(`["A.md","B.md"]`)))
	assert.Empty(t, geminiContextFileName(nil))
}

func TestGeminiMcpServerID(t *testing.T) {
	assert.Equal(t, "gemini.mcpServer/fs", geminiMcpServerID("/root/.gemini/settings.json", "fs"))
	assert.Equal(t, "gemini.mcpServer/fs", geminiMcpServerID("/root/.gemini/antigravity/mcp_config.json", "fs"))
	assert.NotEqual(t, "gemini.mcpServer/fs",
		geminiMcpServerID("/root/.gemini/extensions/a/gemini-extension.json", "fs"))
}
