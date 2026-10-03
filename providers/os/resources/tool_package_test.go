// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A binary name owned by an unrelated package attributes that package to the
// tool: dpkg -S zed on a ZFS host answers zfs-zed.
func TestToolBinaryNamesAvoidCollisions(t *testing.T) {
	colliding := map[string]string{
		"goose":  "pressly/goose DB-migration tool",
		"gemini": "ambiguous across unrelated packages",
		"zed":    "OpenZFS event daemon (zfs-zed)",
	}
	for resource, spec := range toolPackageSpecs {
		for _, bin := range spec.binaryNames {
			owner, ok := colliding[bin]
			assert.False(t, ok, "%s: binary name %q collides with the %s", resource, bin, owner)
		}
	}
}

// Package names as scanned assets report them (product metrics, 2026-09): each
// real install resolves to its tool, and each lookalike to none.
func TestToolPackageCandidates(t *testing.T) {
	owners := func(name string) []string {
		var res []string
		for resource, spec := range toolPackageSpecs {
			if slices.Contains(spec.managerCandidates, name) {
				res = append(res, resource)
			}
		}
		return res
	}
	tests := []struct {
		name string
		tool string // "" when the package is not an AI tool
	}{
		{"claude-code", "claude.code"},        // pkg:brew/homebrew/cask/claude-code
		{"claude-code@latest", "claude.code"}, // pkg:brew/homebrew/cask/claude-code%40latest
		{"Claude Code", "claude.code"},        // pkg:windows/windows/Claude%20Code
		{"Claude CLI", "claude.code"},         // pkg:windows/windows/Claude%20CLI
		{"Claude", "claude.desktop"},          // bundle-id=com.anthropic.claudefordesktop, pkg:appx/windows/Claude
		{"codex", "openai.codex"},             // pkg:brew/homebrew/core/codex
		{"OpenAI.Codex", "openai.codex"},      // pkg:appx/windows/OpenAI.Codex
		{"cursor", "cursor"},                  // pkg:windows/windows/cursor
		{"Cursor", "cursor"},                  // bundle-id=com.todesktop.230313mzl4w4u92
		{"Cursor (User)", "cursor"},           // pkg:windows/windows/Cursor%20%28User%29
		{"block-goose", "goose"},              // pkg:brew/homebrew/cask/block-goose
		{"gemini-cli", "gemini"},              // pkg:brew/homebrew/core/gemini-cli
		{"Windsurf", "windsurf"},              // pkg:macos/macos/Windsurf, pkg:windows/windows/Windsurf
		{"Windsurf (User)", "windsurf"},       // pkg:windows/windows/Windsurf%20%28User%29
		{"zed", "zed"},                        // pkg:brew/homebrew/cask/zed
		{"Zed", "zed"},                        // bundle-id=dev.zed.Zed, pkg:windows/windows/Zed
		{"ZedIndustries.Zed", "zed"},          // pkg:appx/windows/ZedIndustries.Zed
		{"kiro", "kiro"},                      // pkg:brew/homebrew/cask/kiro
		{"Kiro", "kiro"},                      // bundle-id=dev.kiro.desktop
		{"opencode", "opencode"},              // pkg:brew/anomalyco/tap/opencode
		{"opencode-desktop", "opencode"},      // pkg:brew/homebrew/cask/opencode-desktop
		{"OpenCode", "opencode"},              // pkg:windows/windows/OpenCode
		{"antigravity", "antigravity"},        // pkg:brew/homebrew/cask/antigravity
		{"Antigravity", "antigravity"},        // bundle-id=com.google.antigravity
		{"Antigravity (User)", "antigravity"}, // pkg:windows/windows/Antigravity%20%28User%29
		{"Antigravity IDE", "antigravity"},    // bundle-id=com.google.antigravity-ide
		{"OpenClaw", "openclaw"},              // bundle-id=ai.openclaw.mac
		{"Warp", "warp"},                      // bundle-id=dev.warp.Warp-Stable
		{"aider", "aider"},                    // pkg:brew/homebrew/core/aider
		{"ollama", "ollama"},                  // pkg:brew/homebrew/core/ollama
		{"Ollama", "ollama"},                  // bundle-id=com.electron.ollama
		{"ollama-app", "ollama"},              // pkg:brew/homebrew/cask/ollama-app

		{"claude", ""},                       // Claude Code's macOS app AND Claude Desktop's cask
		{"zfs-zed", ""},                      // pkg:deb/debian/zfs-zed, OpenZFS event daemon
		{"Zed Axis 12.2", ""},                // pkg:windows/windows/Zed%20Axis%2012.2
		{"Gemini 2", ""},                     // duplicate-file finder
		{"warp", ""},                         // GNOME Warp on Arch and Alpine; also the terminal's cask
		{"goose", ""},                        // Homebrew formula is pressly/goose (DB migrations)
		{"Cloudflare WARP", ""},              // VPN client
		{"cortex-agent", ""},                 // Palo Alto Cortex XDR agent
		{"Cortex XDR 9.1.0.20483", ""},       // Palo Alto Cortex XDR
		{"adwaita-cursor-theme", ""},         // pkg:rpm/redhat/adwaita-cursor-theme
		{"node-cli-cursor", ""},              // pkg:deb/ubuntu/node-cli-cursor
		{"Microsoft.Copilot", ""},            // Microsoft Copilot, not GitHub Copilot
		{"Claude Code URL Handler", ""},      // bundle-id=com.anthropic.claude-code-url-handler
		{"Microsoft 365 Copilot", ""},        // Microsoft 365 Copilot
		{"@anthropic-ai/claude-code", ""},    // npm, not an OS package
		{"Ollama version 0.34.4", ""},        // version in the name; exact match cannot reach it
		{"Visual Studio Code", ""},           // a runtime host, not a tool
		{"Microsoft Visual Studio Code", ""}, // a runtime host, not a tool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want []string
			if tt.tool != "" {
				want = []string{tt.tool}
			}
			assert.Equal(t, want, owners(tt.name))
		})
	}
	assert.NotContains(t, toolPackageSpecs["zed"].binaryNames, "zed", "zfs-zed owns /usr/sbin/zed")
}

// VS Code and its forks as scanned assets report them, so an IDE-plugin agent
// resolves its host editor on macOS and Windows too.
func TestVSCodeHostCandidates(t *testing.T) {
	for _, name := range []string{
		"code",                                  // pkg:deb/ubuntu/code, pkg:rpm/fedora/code
		"visual-studio-code",                    // pkg:brew/homebrew/cask/visual-studio-code
		"Visual Studio Code",                    // bundle-id=com.microsoft.VSCode
		"Microsoft Visual Studio Code",          // pkg:windows/windows/Microsoft%20Visual%20Studio%20Code
		"Microsoft Visual Studio Code (User)",   // user-scope Windows install
		"Microsoft Visual Studio Code (System)", // system-scope Windows install
		"vscodium",                              // pkg:brew/homebrew/cask/vscodium
		"VSCodium",                              // bundle-id=com.vscodium
		"VSCodium (User)",                       // user-scope Windows install
		"Cursor",                                // bundle-id=com.todesktop.230313mzl4w4u92
		"Windsurf",                              // pkg:macos/macos/Windsurf
	} {
		assert.Contains(t, vscodeHostCandidates, name)
	}
}

func TestVersionCommand(t *testing.T) {
	assert.Equal(t, "/usr/local/bin/ollama --version", versionCommand("/usr/local/bin/ollama"))
	assert.Equal(t, "claude --version", versionCommand("claude"))
	// a path the shell would split is quoted
	assert.Equal(t, "'/opt/ollama app/bin/ollama' --version", versionCommand("/opt/ollama app/bin/ollama"))
}

// The native installer puts the launcher at ~/.local/bin/claude, a symlink to
// ~/.local/share/claude/versions/<version>. The active version is the link
// target, not the highest one kept on disk (layout from a native 2.1.288
// install on Ubuntu 26.04).
func TestClaudeNativeVersionFromLauncherLink(t *testing.T) {
	home := t.TempDir()
	versions := filepath.Join(home, ".local", "share", "claude", "versions")
	require.NoError(t, os.MkdirAll(versions, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o755))
	for _, v := range []string{"2.1.288", "2.1.290"} {
		require.NoError(t, os.WriteFile(filepath.Join(versions, v), []byte("bin"), 0o755))
	}
	require.NoError(t, os.Symlink(filepath.Join(versions, "2.1.288"), filepath.Join(home, ".local", "bin", "claude")))

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	assert.Equal(t, "2.1.288", claudeNativeVersion(afs, filepath.Join(home, ".claude")))
	// A config dir that is not ~/.claude names no home to look in.
	assert.Equal(t, "", claudeNativeVersion(afs, filepath.Join(home, "custom-claude")))
}

// A launcher that points somewhere else (an npm install linked into
// ~/.local/bin) is not the native installer, so its versions dir says nothing.
func TestClaudeNativeVersionLauncherElsewhere(t *testing.T) {
	home := t.TempDir()
	versions := filepath.Join(home, ".local", "share", "claude", "versions")
	require.NoError(t, os.MkdirAll(versions, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(versions, "2.1.288"), []byte("bin"), 0o755))
	other := filepath.Join(home, "npm-claude")
	require.NoError(t, os.WriteFile(other, []byte("bin"), 0o755))
	require.NoError(t, os.Symlink(other, filepath.Join(home, ".local", "bin", "claude")))

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	assert.Equal(t, "", claudeNativeVersion(afs, filepath.Join(home, ".claude")))
}

// Where links cannot be read (an SFTP-style filesystem), the highest version
// in the versions dir stands in, and only while the launcher exists.
func TestClaudeNativeVersionWithoutLinkReader(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	home := "/home/alice"
	versions := home + "/.local/share/claude/versions"
	for _, v := range []string{"2.1.9", "2.1.288", "not-a-version"} {
		require.NoError(t, afs.WriteFile(versions+"/"+v, []byte("bin"), 0o755))
	}
	assert.Equal(t, "", claudeNativeVersion(afs, home+"/.claude"), "no launcher, no install")

	require.NoError(t, afs.WriteFile(home+"/.local/bin/claude", []byte("bin"), 0o755))
	assert.Equal(t, "2.1.288", claudeNativeVersion(afs, home+"/.claude"))
}

func TestClaudeNativeVersionAbsent(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	assert.Equal(t, "", claudeNativeVersion(afs, "/root/.claude"))
}
