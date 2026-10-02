// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// Two users on one host configure the same tool with children that share a
// name. Each test resolves both users' instances in one runtime, as a query
// that covers both users does, and checks that every child reports its own
// user's values: a child id that ignores the parent's configPath makes the
// resource cache hand the first user's child to the second.

var aiTestUsers = []string{"ubuntu", "alice"}

func newAIToolsTestRuntime(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()
	data := &mock.TomlData{Files: map[string]*mock.MockFileData{}}
	for path, content := range files {
		data.Files[path] = &mock.MockFileData{Path: path, Content: content, StatData: mock.FileInfo{Mode: 0o644}}
		// register every parent directory so ReadDir and DirExists work
		for dir := path[:strings.LastIndex(path, "/")]; dir != ""; dir = dir[:strings.LastIndex(dir, "/")] {
			if _, ok := data.Files[dir]; !ok {
				data.Files[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}}
			}
		}
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix"}},
	}, mock.WithData(data))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// perUserFiles expands a file template for each test user; "{u}" is the user.
func perUserFiles(tmpl map[string]string) map[string]string {
	files := map[string]string{}
	for _, u := range aiTestUsers {
		for path, content := range tmpl {
			files[strings.ReplaceAll(path, "{u}", u)] = strings.ReplaceAll(content, "{u}", u)
		}
	}
	return files
}

// childValues resolves the tool for each user in one runtime and returns, per
// user, the value read from that user's child.
func childValues(t *testing.T, rt *plugin.Runtime, tool, configDir string, read func(parent plugin.Resource) (string, string, error)) map[string]string {
	t.Helper()
	got := map[string]string{}
	ids := map[string]string{}
	for _, u := range aiTestUsers {
		parent, err := NewResource(rt, tool, map[string]*llx.RawData{
			"configPath": llx.StringData("/home/" + u + "/" + configDir),
		})
		require.NoError(t, err)
		id, val, err := read(parent)
		require.NoError(t, err, u)
		got[u] = val
		ids[u] = id
	}
	assert.NotEqual(t, ids["ubuntu"], ids["alice"], "child ids of two users' %s must differ", tool)
	return got
}

func assertPerUser(t *testing.T, got map[string]string, format string) {
	t.Helper()
	for _, u := range aiTestUsers {
		assert.Equal(t, fmt.Sprintf(format, u), got[u], "value read for %s", u)
	}
}

// only returns the single element of a child list.
func only[T plugin.Resource](t *testing.T, list []any, err error) (T, error) {
	t.Helper()
	var zero T
	if err != nil {
		return zero, err
	}
	require.Len(t, list, 1)
	return list[0].(T), nil
}

func TestCursorChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.cursor/mcp.json":       `{"mcpServers":{"fs":{"command":"{u}-cmd"}}}`,
		"/home/{u}/.cursor/rules/style.md": "{u} rule",
	}))
	assertPerUser(t, childValues(t, rt, "cursor", ".cursor", func(p plugin.Resource) (string, string, error) {
		c := p.(*mqlCursor)
		l := c.GetMcpServers()
		s, err := only[*mqlCursorMcpServer](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Command.Data, nil
	}), "%s-cmd")
	assertPerUser(t, childValues(t, rt, "cursor", ".cursor", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlCursor).GetRules()
		s, err := only[*mqlCursorRule](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Content.Data, nil
	}), "%s rule")
}

func TestWindsurfChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.codeium/windsurf/mcp_config.json":   `{"mcpServers":{"fs":{"command":"{u}-cmd"}}}`,
		"/home/{u}/.codeium/windsurf/memories/style.md": "{u} rule",
	}))
	assertPerUser(t, childValues(t, rt, "windsurf", ".codeium/windsurf", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlWindsurf).GetMcpServers()
		s, err := only[*mqlWindsurfMcpServer](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Command.Data, nil
	}), "%s-cmd")
	assertPerUser(t, childValues(t, rt, "windsurf", ".codeium/windsurf", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlWindsurf).GetRules()
		s, err := only[*mqlWindsurfRule](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Content.Data, nil
	}), "%s rule")
}

func TestClaudeDesktopChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.config/Claude/claude_desktop_config.json": `{"mcpServers":{"fs":{"command":"{u}-cmd"}}}`,
	}))
	assertPerUser(t, childValues(t, rt, "claude.desktop", ".config/Claude", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlClaudeDesktop).GetMcpServers()
		s, err := only[*mqlClaudeDesktopMcpServer](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Command.Data, nil
	}), "%s-cmd")
}

func TestGeminiChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.gemini/settings.json": `{"mcpServers":{"fs":{"command":"{u}-cmd"}}}`,
	}))
	assertPerUser(t, childValues(t, rt, "gemini", ".gemini", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlGemini).GetMcpServers()
		s, err := only[*mqlGeminiMcpServer](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Command.Data, nil
	}), "%s-cmd")
}

func TestGooseChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.config/goose/config.yaml": "extensions:\n  developer:\n    enabled: true\n    description: {u} ext\n",
	}))
	assertPerUser(t, childValues(t, rt, "goose", ".config/goose", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlGoose).GetExtensions()
		s, err := only[*mqlGooseExtension](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Description.Data, nil
	}), "%s ext")
}

func TestGithubCopilotChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.config/github-copilot/apps.json": `{"github.com:Iv1.b507a08c87ecfe98":{"user":"{u}","githubAppId":"Iv1.b507a08c87ecfe98"}}`,
		"/home/{u}/.config/github-copilot/mcp.json":  `{"servers":{"fs":{"command":"{u}-cmd"}}}`,
	}))
	assertPerUser(t, childValues(t, rt, "github.copilot", ".config/github-copilot", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlGithubCopilot).GetAccounts()
		s, err := only[*mqlGithubCopilotAccount](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.User.Data, nil
	}), "%s")
	assertPerUser(t, childValues(t, rt, "github.copilot", ".config/github-copilot", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlGithubCopilot).GetMcpServers()
		s, err := only[*mqlGithubCopilotMcpServer](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Command.Data, nil
	}), "%s-cmd")
}

func TestGithubCopilotSameServerNameInTwoFiles(t *testing.T) {
	// VS Code's mcp.json and IntelliJ's intellij/mcp.json are separate
	// configurations; a server name used in both is two servers.
	rt := newAIToolsTestRuntime(t, map[string]string{
		"/home/ubuntu/.config/github-copilot/mcp.json":          `{"servers":{"fs":{"command":"vscode-side"}}}`,
		"/home/ubuntu/.config/github-copilot/intellij/mcp.json": `{"servers":{"fs":{"command":"intellij-side"}}}`,
	})
	parent, err := NewResource(rt, "github.copilot", map[string]*llx.RawData{"configPath": llx.StringData("/home/ubuntu/.config/github-copilot")})
	require.NoError(t, err)
	l := parent.(*mqlGithubCopilot).GetMcpServers()
	require.NoError(t, l.Error)
	var cmds []string
	for _, s := range l.Data {
		cmds = append(cmds, s.(*mqlGithubCopilotMcpServer).Command.Data)
	}
	assert.ElementsMatch(t, []string{"vscode-side", "intellij-side"}, cmds)
}

func TestClaudeCodeChildrenPerUser(t *testing.T) {
	files := perUserFiles(map[string]string{
		"/home/{u}/.claude/plugins/installed_plugins.json": `{"version":2,"plugins":{"gopls-lsp@claude-plugins-official":[{"scope":"user","version":"1.0.{u}"}]}}`,
		"/home/{u}/.claude/backups/.claude.json.backup.1759000000000": `{"mcpServers":{"fs":{"command":"{u}-cmd"}},
"projects":{"/srv/shared":{"lastModelUsage":{"claude-opus-4":{"inputTokens":{tokens}}}}}}`,
	})
	// Both users worked in the same project path, with different usage.
	for u, tokens := range map[string]string{"ubuntu": "100", "alice": "7"} {
		p := "/home/" + u + "/.claude/backups/.claude.json.backup.1759000000000"
		files[p] = strings.ReplaceAll(files[p], "{tokens}", tokens)
	}
	rt := newAIToolsTestRuntime(t, files)
	assertPerUser(t, childValues(t, rt, "claude.code", ".claude", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlClaudeCode).GetPlugins()
		s, err := only[*mqlClaudeCodePlugin](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Version.Data, nil
	}), "1.0.%s")
	assertPerUser(t, childValues(t, rt, "claude.code", ".claude", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlClaudeCode).GetMcpServers()
		s, err := only[*mqlClaudeCodeMcpServer](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Command.Data, nil
	}), "%s-cmd")

	tokens := map[string]string{}
	aggregate := map[string]string{}
	for _, u := range aiTestUsers {
		parent, err := NewResource(rt, "claude.code", map[string]*llx.RawData{"configPath": llx.StringData("/home/" + u + "/.claude")})
		require.NoError(t, err)
		cc := parent.(*mqlClaudeCode)
		projects := cc.GetProjects()
		proj, err := only[*mqlClaudeCodeProject](t, projects.Data, projects.Error)
		require.NoError(t, err)
		models := proj.GetModels()
		m, err := only[*mqlClaudeCodeModelUsage](t, models.Data, models.Error)
		require.NoError(t, err)
		tokens[u] = fmt.Sprint(m.InputTokens.Data)

		all := cc.GetModels()
		m, err = only[*mqlClaudeCodeModelUsage](t, all.Data, all.Error)
		require.NoError(t, err)
		aggregate[u] = fmt.Sprint(m.InputTokens.Data)
	}
	assert.Equal(t, map[string]string{"ubuntu": "100", "alice": "7"}, tokens, "per-project usage")
	assert.Equal(t, map[string]string{"ubuntu": "100", "alice": "7"}, aggregate, "instance-wide usage")
}

func TestOpenaiCodexChildrenPerUser(t *testing.T) {
	files := perUserFiles(map[string]string{
		"/home/{u}/.codex/config.toml":                           "[mcp_servers.fs]\ncommand = \"{u}-cmd\"\n",
		"/home/{u}/.codex/.tmp/plugins/plugins/github/.mcp.json": `{"mcpServers":{"gh":{"command":"{u}-plugin-cmd"}}}`,
		"/home/{u}/.codex/.tmp/plugins/plugins/github/.app.json": `{"apps":{"github":{"id":"{u}-connector"}}}`,
	})
	// Only alice's plugin ships hooks.
	files["/home/alice/.codex/.tmp/plugins/plugins/github/hooks.json"] = "{}"
	rt := newAIToolsTestRuntime(t, files)

	assertPerUser(t, childValues(t, rt, "openai.codex", ".codex", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlOpenaiCodex).GetMcpServers()
		if l.Error != nil {
			return "", "", l.Error
		}
		for _, raw := range l.Data {
			s := raw.(*mqlOpenaiCodexMcpServer)
			if s.Name.Data == "fs" {
				return s.MqlID(), s.Command.Data, nil
			}
		}
		return "", "", fmt.Errorf("fs server missing")
	}), "%s-cmd")
	assertPerUser(t, childValues(t, rt, "openai.codex", ".codex", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlOpenaiCodex).GetMcpServers()
		if l.Error != nil {
			return "", "", l.Error
		}
		for _, raw := range l.Data {
			s := raw.(*mqlOpenaiCodexMcpServer)
			if s.Name.Data == "gh" {
				return s.MqlID(), s.Command.Data, nil
			}
		}
		return "", "", fmt.Errorf("gh server missing")
	}), "%s-plugin-cmd")
	assertPerUser(t, childValues(t, rt, "openai.codex", ".codex", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlOpenaiCodex).GetConnectors()
		s, err := only[*mqlOpenaiCodexConnector](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Id.Data, nil
	}), "%s-connector")

	hooks := childValues(t, rt, "openai.codex", ".codex", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlOpenaiCodex).GetPlugins()
		s, err := only[*mqlOpenaiCodexPlugin](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), fmt.Sprint(s.HasHooks.Data), nil
	})
	assert.Equal(t, map[string]string{"ubuntu": "false", "alice": "true"}, hooks)
}
