// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAfero returns an afero.Afero backed by the real OS filesystem,
// suitable for unit tests that create temp directories.
func testAfero() *afero.Afero {
	return &afero.Afero{Fs: afero.NewOsFs()}
}

// createTestClaudeConfig creates a temporary directory tree mimicking a Claude Code
// config directory and returns its path. The caller should defer os.RemoveAll(path).
func createTestClaudeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// settings.json
	writeTestFile(t, dir, "settings.json", `{
		"enabledPlugins": {
			"gopls-lsp@official": true,
			"frontend-design@official": true
		}
	}`)

	// plugins/installed_plugins.json
	mkdirAllTest(t, dir, "plugins")
	writeTestFile(t, dir, "plugins/installed_plugins.json", `{
		"version": 2,
		"plugins": {
			"gopls-lsp@official": [{
				"scope": "user",
				"installPath": "/home/test/.claude/plugins/cache/gopls-lsp/1.0.0",
				"version": "1.0.0",
				"installedAt": "2026-01-01T00:00:00Z",
				"lastUpdated": "2026-01-01T00:00:00Z",
				"gitCommitSha": "abc123"
			}],
			"frontend-design@official": [{
				"scope": "user",
				"installPath": "/home/test/.claude/plugins/cache/frontend-design/2.0.0",
				"version": "2.0.0",
				"installedAt": "2026-02-01T00:00:00Z",
				"lastUpdated": "2026-02-01T00:00:00Z",
				"gitCommitSha": "def456"
			}]
		}
	}`)

	// backups with account info
	mkdirAllTest(t, dir, "backups")
	writeTestFile(t, dir, "backups/.claude.json.backup.1000000000000", `{
		"oauthAccount": {
			"accountUuid": "test-uuid-1234",
			"emailAddress": "test@example.com",
			"organizationUuid": "org-uuid-5678",
			"billingType": "team",
			"organizationRole": "owner",
			"organizationName": "TestOrg"
		},
		"projects": {
			"/home/test/project-one": {},
			"/home/test/go/src/github.com/user/repo": {}
		},
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {}
			},
			"claude.ai HubSpot": {
				"type": "http",
				"url": "https://mcp.hubspot.com/mcp",
				"env": {"HUBSPOT_TOKEN": "secret"}
			}
		}
	}`)

	// skills
	mkdirAllTest(t, dir, "skills/review-pr")
	writeTestFile(t, dir, "skills/review-pr/SKILL.md", `---
name: review-pr
description: Review a pull request.
allowed-tools: Bash(gh *), Read, Grep
argument-hint: "<pr-number>"
---

# Review PR
`)

	// projects directories (matching the backup paths)
	mkdirAllTest(t, dir, "projects/-home-test-project-one")
	mkdirAllTest(t, dir, "projects/-home-test-go-src-github-com-user-repo/memory")
	writeTestFile(t, dir, "projects/-home-test-go-src-github-com-user-repo/memory/note.md", "test memory")

	// mcp-needs-auth-cache.json
	writeTestFile(t, dir, "mcp-needs-auth-cache.json", `{
		"claude.ai HubSpot": {"timestamp": 1700000000000},
		"claude.ai Gmail": {"timestamp": 1700000001000}
	}`)

	return dir
}

func mkdirAllTest(t *testing.T, base string, rel string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(base, rel), 0o755))
}

func writeTestFile(t *testing.T, base string, rel string, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(base, rel), []byte(content), 0o644))
}

func TestParseSkillMd(t *testing.T) {
	content := `---
name: review-pr
description: Review a pull request or branch using a structured checklist.
allowed-tools: Bash(gh *), Bash(git *), Read, Grep, Glob
argument-hint: "<pr-number-or-branch> [--focus area]"
---

# Pull Request Review

Review a PR or branch diff.
`

	skill := parseSkillMd("review-pr", "/home/user/.claude/skills/review-pr/SKILL.md", content)

	assert.Equal(t, "review-pr", skill.name)
	assert.Equal(t, "Review a pull request or branch using a structured checklist.", skill.description)
	require.Len(t, skill.allowedTools, 5)
	assert.Equal(t, "Bash(gh *)", skill.allowedTools[0])
	assert.Equal(t, "Bash(git *)", skill.allowedTools[1])
	assert.Equal(t, "Read", skill.allowedTools[2])
	assert.Equal(t, "Grep", skill.allowedTools[3])
	assert.Equal(t, "Glob", skill.allowedTools[4])
	assert.Equal(t, "<pr-number-or-branch> [--focus area]", skill.argumentHint)
	assert.Equal(t, "/home/user/.claude/skills/review-pr/SKILL.md", skill.source)
	assert.Equal(t, content, skill.content)
}

func TestParseSkillMdNoFrontmatter(t *testing.T) {
	content := "# Just a markdown file\n\nNo frontmatter here."
	skill := parseSkillMd("test", "/path/to/skill", content)

	assert.Equal(t, "test", skill.name)
	assert.Equal(t, "", skill.description)
	assert.Nil(t, skill.allowedTools)
}

func TestPathToProjectDir(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/pub/go/src/go.mondoo.com/mql", "-pub-go-src-go-mondoo-com-mql"},
		{"/home/user/projects", "-home-user-projects"},
		{"/pub/git/setup", "-pub-git-setup"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := pathToProjectDir(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDirHasFilesAfero(t *testing.T) {
	afs := testAfero()

	assert.False(t, dirHasFilesAfero(afs, "/nonexistent/path"))

	dir := t.TempDir()
	assert.False(t, dirHasFilesAfero(afs, dir))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hi"), 0o644))
	assert.True(t, dirHasFilesAfero(afs, dir))
}

func TestReadJSONFileAfero(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()
	writeTestFile(t, dir, "test.json", `{"key": "value"}`)

	var result map[string]string
	err := readJSONFileAfero(afs, dir, "test.json", &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])

	err = readJSONFileAfero(afs, dir, "nonexistent.json", &result)
	assert.True(t, os.IsNotExist(err))
}

func TestFindLatestBackupAfero(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()
	mkdirAllTest(t, dir, "backups")

	writeTestFile(t, dir, "backups/.claude.json.backup.1000000000000", "{}")
	writeTestFile(t, dir, "backups/.claude.json.backup.2000000000000", "{}")
	writeTestFile(t, dir, "backups/.claude.json.backup.1500000000000", "{}")

	latest, err := findLatestBackupAfero(afs, dir)
	require.NoError(t, err)
	assert.Equal(t, ".claude.json.backup.2000000000000", latest)
}

func TestFindLatestBackupAferoEmpty(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()
	mkdirAllTest(t, dir, "backups")

	_, err := findLatestBackupAfero(afs, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backup files found")
	// An empty backups dir is the benign "no history" case: callers suppress it
	// via errors.Is(err, os.ErrNotExist) while still surfacing real failures.
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestFindLatestBackupAferoMissingDir(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	// No backups dir at all: also the benign not-exist case.
	_, err := findLatestBackupAfero(afs, dir)
	assert.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestIsSystemHomeDir(t *testing.T) {
	// Empty or missing
	assert.True(t, isSystemHomeDir(""))

	// macOS system accounts
	assert.True(t, isSystemHomeDir("/var/db/astris"))
	assert.True(t, isSystemHomeDir("/var/db/analyticsd"))
	assert.True(t, isSystemHomeDir("/var/empty"))
	assert.True(t, isSystemHomeDir("/var/virusmails"))
	assert.True(t, isSystemHomeDir("/Library/WebServer"))
	assert.True(t, isSystemHomeDir("/nonexistent"))
	assert.True(t, isSystemHomeDir("/dev/null"))
	assert.True(t, isSystemHomeDir("/"))

	// Linux system accounts
	assert.True(t, isSystemHomeDir("/usr/share"))
	assert.True(t, isSystemHomeDir("/bin/false"))
	assert.True(t, isSystemHomeDir("/sbin/nologin"))
	assert.True(t, isSystemHomeDir("/var/run/something"))

	// Paths that look like root but aren't
	assert.True(t, isSystemHomeDir("/rootfs"))
	assert.True(t, isSystemHomeDir("/rootkit"))

	// Real user home directories should NOT be flagged
	assert.False(t, isSystemHomeDir("/Users/chris"))
	assert.False(t, isSystemHomeDir("/Users/admin"))
	assert.False(t, isSystemHomeDir("/home/chris"))
	assert.False(t, isSystemHomeDir("/root"))
	assert.False(t, isSystemHomeDir("/root/.config"))
	assert.False(t, isSystemHomeDir("/usr/home/freebsd"))
	assert.False(t, isSystemHomeDir(`C:\Users\chris`))
	// Windows homes match regardless of drive case or slash direction
	assert.False(t, isSystemHomeDir(`c:\users\chris`))
	assert.False(t, isSystemHomeDir("C:/Users/chris"))
}

func TestClaudeConfigIntegration(t *testing.T) {
	afs := testAfero()
	dir := createTestClaudeConfig(t)

	// Test settings reading
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	err := readJSONFileAfero(afs, dir, "settings.json", &settings)
	require.NoError(t, err)
	assert.True(t, settings.EnabledPlugins["gopls-lsp@official"])
	assert.True(t, settings.EnabledPlugins["frontend-design@official"])

	// Test backup state loading
	latest, err := findLatestBackupAfero(afs, dir)
	require.NoError(t, err)

	var state claudeBackupState
	err = readJSONFileAfero(afs, dir, filepath.Join("backups", latest), &state)
	require.NoError(t, err)
	require.NotNil(t, state.OAuthAccount)
	assert.Equal(t, "test@example.com", state.OAuthAccount.EmailAddress)
	assert.Equal(t, "TestOrg", state.OAuthAccount.OrganizationName)
	assert.Equal(t, "owner", state.OAuthAccount.OrganizationRole)
	assert.Equal(t, "team", state.OAuthAccount.BillingType)
	assert.Equal(t, "test-uuid-1234", state.OAuthAccount.AccountUuid)
	assert.Equal(t, "org-uuid-5678", state.OAuthAccount.OrganizationUuid)

	// MCP servers come from .claude.json (backup state), independent of the
	// needs-auth cache: the stdio "filesystem" server does not need auth yet
	// must still be visible.
	require.Len(t, state.McpServers, 2)
	fsSrv := state.McpServers["filesystem"]
	assert.Equal(t, "npx", fsSrv.Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, fsSrv.Args)
	assert.Empty(t, fsSrv.URL)
	assert.Equal(t, mcpTransportStdio, deriveMcpTransport(fsSrv.Type, fsSrv.Command, fsSrv.URL))
	hubSrv := state.McpServers["claude.ai HubSpot"]
	assert.Equal(t, "http", hubSrv.Type)
	assert.Equal(t, "https://mcp.hubspot.com/mcp", hubSrv.URL)
	assert.NotEmpty(t, hubSrv.Env)

	// Test project dir mapping
	dirMap := state.projectDirMap()
	assert.Equal(t, "-home-test-project-one", dirMap["/home/test/project-one"])
	assert.Equal(t, "-home-test-go-src-github-com-user-repo", dirMap["/home/test/go/src/github.com/user/repo"])

	// Test memory detection
	assert.False(t, dirHasFilesAfero(afs, filepath.Join(dir, "projects", "-home-test-project-one", "memory")))
	assert.True(t, dirHasFilesAfero(afs, filepath.Join(dir, "projects", "-home-test-go-src-github-com-user-repo", "memory")))

	// Test skill parsing from fixture
	skillPath := filepath.Join(dir, "skills", "review-pr", "SKILL.md")
	data, err := afs.ReadFile(skillPath)
	require.NoError(t, err)
	skill := parseSkillMd("review-pr", skillPath, string(data))
	assert.Equal(t, "review-pr", skill.name)
	assert.Equal(t, "Review a pull request.", skill.description)
	require.Len(t, skill.allowedTools, 3)
	assert.Equal(t, "Bash(gh *)", skill.allowedTools[0])
	assert.Equal(t, "<pr-number>", skill.argumentHint)

	// Test MCP auth cache reading
	var cache map[string]struct {
		Timestamp int64 `json:"timestamp"`
	}
	err = readJSONFileAfero(afs, dir, "mcp-needs-auth-cache.json", &cache)
	require.NoError(t, err)
	assert.Len(t, cache, 2)
	assert.Equal(t, int64(1700000000000), cache["claude.ai HubSpot"].Timestamp)
}

func TestParseGitRemoteURL(t *testing.T) {
	cases := []struct {
		remote   string
		wantHost string
		wantName string
	}{
		{"git@github.com:mondoohq/mql.git", "github.com", "mondoohq/mql"},
		{"https://github.com/mondoohq/mql.git", "github.com", "mondoohq/mql"},
		{"https://github.com/mondoohq/mql", "github.com", "mondoohq/mql"},
		{"ssh://git@gitlab.com:2222/group/sub/proj.git", "gitlab.com", "group/sub/proj"},
		{"https://user:token@github.com/owner/repo.git", "github.com", "owner/repo"},
		{"", "", ""},
		{"not-a-url", "", ""},
	}
	for _, c := range cases {
		host, name := parseGitRemoteURL(c.remote)
		assert.Equal(t, c.wantHost, host, "host for %q", c.remote)
		assert.Equal(t, c.wantName, name, "name for %q", c.remote)
	}
}

func TestGitRepoInfo(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	// a project directory that is a git working tree with origin + upstream
	mkdirAllTest(t, dir, "repo/.git")
	mkdirAllTest(t, dir, "repo/subdir")
	writeTestFile(t, dir, "repo/.git/config", `[core]
	bare = false
[remote "origin"]
	url = git@github.com:mondoohq/mql.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[remote "upstream"]
	url = https://github.com/other/mql.git
`)
	writeTestFile(t, dir, "repo/.git/HEAD", "ref: refs/heads/dom/feature\n")

	repoRoot := filepath.Join(dir, "repo")

	info, ok := gitRepoInfo(afs, repoRoot)
	require.True(t, ok)
	assert.Equal(t, repoRoot, info.root)
	assert.Equal(t, "git@github.com:mondoohq/mql.git", info.url)
	assert.Equal(t, "github.com", info.host)
	assert.Equal(t, "mondoohq/mql", info.name)
	assert.Equal(t, "dom/feature", info.branch)
	assert.Equal(t, map[string]string{
		"origin":   "git@github.com:mondoohq/mql.git",
		"upstream": "https://github.com/other/mql.git",
	}, info.remotes)

	// a subdirectory of the repo resolves to the same working-tree root
	sub, ok := gitRepoInfo(afs, filepath.Join(repoRoot, "subdir"))
	require.True(t, ok)
	assert.Equal(t, repoRoot, sub.root)

	// a non-git directory yields ok=false
	mkdirAllTest(t, dir, "plain")
	_, ok = gitRepoInfo(afs, filepath.Join(dir, "plain"))
	assert.False(t, ok)
}

func TestParseGitHeadBranch(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	writeTestFile(t, dir, "HEAD", "ref: refs/heads/main\n")
	assert.Equal(t, "main", parseGitHeadBranch(afs, filepath.Join(dir, "HEAD")))

	writeTestFile(t, dir, "DETACHED", "9fceb02d0ae598e95dc970b74767f19372d61af8\n")
	assert.Equal(t, "", parseGitHeadBranch(afs, filepath.Join(dir, "DETACHED")))

	assert.Equal(t, "", parseGitHeadBranch(afs, filepath.Join(dir, "missing")))
}

func TestParseGitRemotesNoOriginFallback(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()
	mkdirAllTest(t, dir, "repo/.git")
	writeTestFile(t, dir, "repo/.git/config", `[remote "upstream"]
	url = git@gitlab.com:group/proj.git
`)
	writeTestFile(t, dir, "repo/.git/HEAD", "ref: refs/heads/main\n")

	info, ok := gitRepoInfo(afs, filepath.Join(dir, "repo"))
	require.True(t, ok)
	// no origin: falls back to the only remote present
	assert.Equal(t, "git@gitlab.com:group/proj.git", info.url)
	assert.Equal(t, "gitlab.com", info.host)
}

func TestGitRepoInfoWorktree(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	// main checkout: .git directory holds the shared config
	mkdirAllTest(t, dir, "main/.git")
	writeTestFile(t, dir, "main/.git/config", `[remote "origin"]
	url = git@github.com:mondoohq/mql.git
`)
	writeTestFile(t, dir, "main/.git/HEAD", "ref: refs/heads/main\n")

	// per-worktree git dir under .git/worktrees/<name>
	mkdirAllTest(t, dir, "main/.git/worktrees/feature")
	writeTestFile(t, dir, "main/.git/worktrees/feature/HEAD", "ref: refs/heads/dom/feature\n")
	writeTestFile(t, dir, "main/.git/worktrees/feature/commondir", "../..\n")

	// linked worktree checkout: .git is a pointer file
	mkdirAllTest(t, dir, "wt")
	worktreeGitDir := filepath.Join(dir, "main/.git/worktrees/feature")
	writeTestFile(t, dir, "wt/.git", "gitdir: "+worktreeGitDir+"\n")

	info, ok := gitRepoInfo(afs, filepath.Join(dir, "wt"))
	require.True(t, ok)
	assert.Equal(t, filepath.Join(dir, "wt"), info.root)
	// config comes from the shared common dir
	assert.Equal(t, "git@github.com:mondoohq/mql.git", info.url)
	assert.Equal(t, "mondoohq/mql", info.name)
	// HEAD is read per-worktree
	assert.Equal(t, "dom/feature", info.branch)
}

// Claude Code has three MCP scopes: user (top-level mcpServers in .claude.json),
// local (projects[<path>].mcpServers in .claude.json), and project (the
// project's own .mcp.json). All three must be reported, each scoped server
// carrying its project path.
func TestClaudeMcpServersScopes(t *testing.T) {
	afs := testAfero()
	project := t.TempDir()
	writeTestFile(t, project, ".mcp.json", `{"mcpServers":{
		"filesystem": {"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","."]},
		"memory": {"command":"npx","args":["-y","@modelcontextprotocol/server-memory@0.5.0"]}
	}}`)
	other := t.TempDir() // a project without an .mcp.json

	var state claudeBackupState
	require.NoError(t, json.Unmarshal([]byte(`{
		"mcpServers": {
			"filesystem": {"type":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/home/alice"]}
		},
		"projects": {
			`+jsonString(project)+`: {
				"hasTrustDialogAccepted": true,
				"mcpServers": {
					"memory": {"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]}
				}
			},
			`+jsonString(other)+`: {"hasTrustDialogAccepted": true}
		}
	}`), &state))

	servers := claudeMcpServers(afs, &state)

	type row struct{ project, name, lastArg string }
	var got []row
	for _, s := range servers {
		got = append(got, row{s.project, s.name, s.entry.Args[len(s.entry.Args)-1]})
	}
	assert.Equal(t, []row{
		{"", "filesystem", "/home/alice"},
		{project, "filesystem", "."},
		// local (.claude.json) takes precedence over the project's .mcp.json
		{project, "memory", "@modelcontextprotocol/server-memory"},
	}, got)
}

// A name in the needs-auth cache that a project scope already defines is that
// project's server: it must not come back a second time as a user-scope server.
// Only a name no scope defines is added, once, without connection details.
func TestWithAuthCacheOnlyServers(t *testing.T) {
	servers := []claudeScopedMcpServer{
		{name: "filesystem"},
		{project: "/home/alice/src/api", name: "memory"},
	}
	got := withAuthCacheOnlyServers(servers, []string{"memory", "zeta", "filesystem", "alpha", "zeta"})

	type row struct{ project, name string }
	var rows []row
	for _, s := range got {
		rows = append(rows, row{s.project, s.name})
	}
	assert.Equal(t, []row{
		{"", "filesystem"},
		{"/home/alice/src/api", "memory"},
		{"", "alpha"},
		{"", "zeta"},
	}, rows)
}

func TestClaudeMcpServerID(t *testing.T) {
	assert.Equal(t, "claude.code.mcpServer/memory", claudeMcpServerID("", "memory"),
		"user-scope ids must not change")
	assert.Equal(t, "claude.code.mcpServer//home/alice/src/api/memory", claudeMcpServerID("/home/alice/src/api", "memory"))
	assert.NotEqual(t, claudeMcpServerID("/a", "memory"), claudeMcpServerID("/b", "memory"))
}

func TestClaudeMcpServersMalformedProjectFile(t *testing.T) {
	project := t.TempDir()
	writeTestFile(t, project, ".mcp.json", `{"mcpServers": {`)
	state := claudeBackupState{Projects: map[string]claudeProjectEntry{project: {}}}
	assert.Empty(t, claudeMcpServers(testAfero(), &state), "an unparsable .mcp.json contributes nothing")
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
