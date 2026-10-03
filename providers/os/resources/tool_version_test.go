// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// npmGlobalTree lays out `npm install -g @anthropic-ai/claude-code @openai/codex`
// as found on RHEL 7.9 (package.json heads copied from that host).
func npmGlobalTree(t *testing.T) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	files := map[string]string{
		"/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json": `{
  "name": "@anthropic-ai/claude-code",
  "version": "2.1.197",
  "bin": {
    "claude": "bin/claude.exe"
  }
}`,
		"/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe": "ELF",
		"/usr/local/lib/node_modules/@openai/codex/package.json": `{
  "name": "@openai/codex",
  "version": "0.160.0",
  "description": "Codex CLI is a coding agent from OpenAI that runs locally on your computer.",
  "bin": {
    "codex": "bin/codex.js"
  },
  "type": "module"
}`,
		"/usr/local/lib/node_modules/@openai/codex/bin/codex.js": "#!/usr/bin/env node\n",
		// a package.json above the package, which must not be read
		"/usr/local/lib/package.json": `{"name": "@openai/codex", "version": "9.9.9"}`,
		// the native installer keeps each release as a bare binary
		"/home/alice/.local/share/claude/versions/2.1.197": "ELF",
		"/home/alice/.local/share/package.json":            `{"name": "@anthropic-ai/claude-code", "version": "1.0.0"}`,
	}
	for p, content := range files {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	return afs
}

func TestNpmPackageVersion(t *testing.T) {
	afs := npmGlobalTree(t)

	assert.Equal(t, "2.1.197", npmPackageVersion(afs,
		"/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", "@anthropic-ai/claude-code"))
	// codex is a #!/usr/bin/env node script: under sudo's secure_path a node
	// that lives only in /usr/local/bin is not found, so running it fails
	assert.Equal(t, "0.160.0", npmPackageVersion(afs,
		"/usr/local/lib/node_modules/@openai/codex/bin/codex.js", "@openai/codex"))

	// a binary of another package is not ours
	assert.Empty(t, npmPackageVersion(afs,
		"/usr/local/lib/node_modules/@openai/codex/bin/codex.js", "@anthropic-ai/claude-code"))
	// only node_modules/<name>/package.json counts, never one above it
	assert.Empty(t, npmPackageVersion(afs, "/usr/local/lib/node_modules/codex", "@openai/codex"))
	// not inside an npm package
	assert.Empty(t, npmPackageVersion(afs, "/home/alice/.local/share/claude/versions/2.1.197", "@anthropic-ai/claude-code"))
	assert.Empty(t, npmPackageVersion(afs, "/usr/bin/codex", "@openai/codex"))
}

func TestNpmPackageVersionRejectsNonSemver(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.WriteFile("/n/node_modules/@openai/codex/package.json", []byte(`{"name":"@openai/codex","version":"not a version"}`), 0o644))
	assert.Empty(t, npmPackageVersion(afs, "/n/node_modules/@openai/codex/bin/codex.js", "@openai/codex"))
	// a package.json that names another package is not trusted for this one
	require.NoError(t, afs.WriteFile("/m/node_modules/@openai/codex/package.json", []byte(`{"name":"@openai/codex-sdk","version":"1.0.0"}`), 0o644))
	assert.Empty(t, npmPackageVersion(afs, "/m/node_modules/@openai/codex/bin/codex.js", "@openai/codex"))
}

func TestParseToolVersionOutput(t *testing.T) {
	assert.Equal(t, "2.1.197", parseClaudeVersion("2.1.197 (Claude Code)\n"))
	assert.Empty(t, parseClaudeVersion(""))
	assert.Empty(t, parseClaudeVersion("error: unknown option\n"))
	assert.Equal(t, "0.160.0", parseCodexVersion("codex-cli 0.160.0\n"))
	assert.Empty(t, parseCodexVersion("env: node: No such file or directory\n"))
}
