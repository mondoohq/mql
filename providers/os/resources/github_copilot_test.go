// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func createTestCopilotConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeTestFile(t, dir, "apps.json", `{
		"github.com:Iv23ctfURkiMfJ4xr5mv": {
			"oauth_token": "ghu_test123",
			"user": "testuser",
			"githubAppId": "Iv23ctfURkiMfJ4xr5mv"
		},
		"github.com:Ov23liV9UpD7Rnfnskm3": {
			"user": "testuser",
			"oauth_token": "gho_test456",
			"githubAppId": "Ov23liV9UpD7Rnfnskm3"
		}
	}`)

	mkdirAllTest(t, dir, "intellij")
	writeTestFile(t, dir, "intellij/mcp.json", `{
		"servers": {
			"my-server": {
				"type": "stdio",
				"command": "my-command",
				"args": ["--flag"],
				"env": {"API_KEY": "secret"}
			},
			"remote": {
				"type": "http",
				"url": "https://mcp.example.com/mcp"
			}
		}
	}`)

	return dir
}

func TestCopilotAppsParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCopilotConfig(t)

	data, err := afs.ReadFile(filepath.Join(dir, "apps.json"))
	require.NoError(t, err)

	var apps map[string]copilotApp
	err = json.Unmarshal(data, &apps)
	require.NoError(t, err)
	assert.Len(t, apps, 2)

	app := apps["github.com:Iv23ctfURkiMfJ4xr5mv"]
	assert.Equal(t, "testuser", app.User)
	assert.Equal(t, "Iv23ctfURkiMfJ4xr5mv", app.GitHubAppID)
	assert.Equal(t, "ghu_test123", app.OAuthToken)
}

func TestCopilotMCPParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestCopilotConfig(t)

	data, err := afs.ReadFile(filepath.Join(dir, "intellij", "mcp.json"))
	require.NoError(t, err)

	var config copilotMCPConfig
	err = json.Unmarshal(data, &config)
	require.NoError(t, err)
	assert.Len(t, config.Servers, 2)

	server := config.Servers["my-server"]
	assert.Equal(t, "stdio", server.Type)
	assert.Equal(t, "my-command", server.Command)
	assert.Equal(t, []string{"--flag"}, server.Args)
	assert.NotEmpty(t, server.Env)

	remote := config.Servers["remote"]
	assert.Equal(t, "http", remote.Type)
	assert.Equal(t, "https://mcp.example.com/mcp", remote.URL)
	assert.Empty(t, remote.Command)
}

func TestCopilotConfigMissing(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	_, err := afs.ReadFile(filepath.Join(dir, "apps.json"))
	assert.Error(t, err)
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
