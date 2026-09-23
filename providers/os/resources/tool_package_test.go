// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOllamaVersion(t *testing.T) {
	// What `ollama --version` prints when no server is reachable, captured from
	// ollama 0.32.14. Both lines go to stdout and the exit status is 0, so the
	// warning is not a failure signal.
	assert.Equal(t, "0.32.14", parseOllamaVersion(
		"Warning: could not connect to a running Ollama instance\nWarning: client version is 0.32.14\n"))

	// What it prints when one is.
	assert.Equal(t, "0.32.14", parseOllamaVersion("ollama version is 0.32.14\n"))

	// With OLLAMA_HOST pointing at another machine both lines appear. The
	// client line is the binary installed here, which is what the package
	// version has to describe; the server line belongs to a different host.
	assert.Equal(t, "0.31.0", parseOllamaVersion(
		"ollama version is 0.32.14\nWarning: client version is 0.31.0\n"))

	for _, in := range []string{"", "\n", "command not found", "ollama version is"} {
		assert.Empty(t, parseOllamaVersion(in), "input %q", in)
	}
}

func writeVSCodeExtension(t *testing.T, home, editorDir, dirName, packageJSON string) {
	t.Helper()
	rel := filepath.Join(editorDir, dirName)
	mkdirAllTest(t, home, rel)
	writeTestFile(t, home, filepath.Join(rel, "package.json"), packageJSON)
}

// An IDE-plugin agent is present when its VS Code extension is installed, even
// without its own config directory, and the extension supplies the version.
func TestFindVSCodeExtension(t *testing.T) {
	afs := testAfero()
	alice, bob := t.TempDir(), t.TempDir()
	writeVSCodeExtension(t, alice, ".vscode/extensions", "saoudrizwan.claude-dev-4.1.19",
		`{"name":"claude-dev","publisher":"saoudrizwan","version":"4.1.19"}`)
	writeVSCodeExtension(t, bob, ".cursor/extensions", "saoudrizwan.claude-dev-4.1.20",
		`{"name":"claude-dev","publisher":"saoudrizwan","version":"4.1.20"}`)
	// Same prefix, different extension: must not count as Cline.
	writeVSCodeExtension(t, alice, ".vscode/extensions", "saoudrizwan.claude-devtools-1.0.0",
		`{"name":"claude-devtools","publisher":"saoudrizwan","version":"9.9.9"}`)

	v, ok := findVSCodeExtension(afs, []string{alice, bob}, []string{"saoudrizwan.claude-dev"})
	assert.True(t, ok)
	assert.Equal(t, "4.1.20", v, "the highest installed version across users and editors")

	_, ok = findVSCodeExtension(afs, []string{alice, bob}, []string{"Continue.continue"})
	assert.False(t, ok)
}

// Marketplace ids are case-insensitive; the folder is lower-case while the
// package.json publisher keeps its case. Folder name and package.json as a
// Windows VS Code install of Continue writes them.
func TestFindVSCodeExtensionCaseInsensitive(t *testing.T) {
	home := t.TempDir()
	writeVSCodeExtension(t, home, ".vscode/extensions", "continue.continue-2.0.0-win32-x64",
		`{"name":"continue","publisher":"Continue","version":"2.0.0"}`)

	v, ok := findVSCodeExtension(testAfero(), []string{home}, []string{"Continue.continue"})
	assert.True(t, ok)
	assert.Equal(t, "2.0.0", v)
}

// A directory named like the extension whose package.json names another one
// (or has none) is not the extension.
func TestFindVSCodeExtensionChecksPackageJSON(t *testing.T) {
	home := t.TempDir()
	writeVSCodeExtension(t, home, ".vscode/extensions", "saoudrizwan.claude-dev-4.1.20",
		`{"name":"other","publisher":"someone","version":"1.0.0"}`)
	mkdirAllTest(t, home, ".vscode/extensions/saoudrizwan.claude-dev-4.1.19")

	_, ok := findVSCodeExtension(testAfero(), []string{home}, []string{"saoudrizwan.claude-dev"})
	assert.False(t, ok)
}

func TestSemverLess(t *testing.T) {
	assert.True(t, semverLess("3.9.0", "3.10.0"), "numeric, not lexical")
	assert.False(t, semverLess("3.10.0", "3.9.0"))
	assert.False(t, semverLess("1.0.0", "1.0.0"))
}
