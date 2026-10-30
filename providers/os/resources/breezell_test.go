// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// newBreezell returns a breezell resource for /home/dev/.breezell on a mock
// Linux connection holding files and the (listable) directories dirs.
func newBreezell(t *testing.T, files map[string]string, dirs ...string) *mqlBreezell {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for path, content := range files {
		mockFiles[path] = &mock.MockFileData{Path: path, Content: content}
	}
	for _, dir := range dirs {
		mockFiles[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}}
	}
	pf := &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}}
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(&mock.TomlData{Files: mockFiles}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	res, err := NewResource(runtime, "breezell", map[string]*llx.RawData{
		"configPath": llx.StringData("/home/dev/.breezell"),
	})
	require.NoError(t, err)
	return res.(*mqlBreezell)
}

func TestBreezellMCPServersFromEditorDataDir(t *testing.T) {
	r := newBreezell(t, map[string]string{
		// The user mcp.json sits in .breezell-editor, not the .breezell config dir.
		"/home/dev/.breezell-editor/mcp.json": `{
			"mcpServers": {
				"github": {
					"command": "npx",
					"args": ["-y", "@modelcontextprotocol/server-github"],
					"env": {"GITHUB_TOKEN": "x"}
				},
				"docs": {"type": "http", "url": "https://mcp.example.com/mcp"}
			}
		}`,
		"/home/dev/.breezell/mcp.json": `{"mcpServers": {"decoy": {"command": "nope"}}}`,
	})

	servers, err := r.mcpServers()
	require.NoError(t, err)
	require.Len(t, servers, 2)

	byName := map[string]*mqlBreezellMcpServer{}
	for _, s := range servers {
		srv := s.(*mqlBreezellMcpServer)
		byName[srv.Name.Data] = srv
	}
	require.Contains(t, byName, "github")
	require.Contains(t, byName, "docs")

	gh := byName["github"]
	assert.Equal(t, mcpTransportStdio, gh.Type.Data)
	assert.Equal(t, "npx", gh.Command.Data)
	assert.Equal(t, []any{"-y", "@modelcontextprotocol/server-github"}, gh.Args.Data)
	assert.True(t, gh.HasEnv.Data)

	docs := byName["docs"]
	assert.Equal(t, mcpTransportHTTP, docs.Type.Data)
	assert.Equal(t, "https://mcp.example.com/mcp", docs.Url.Data)
	assert.False(t, docs.HasEnv.Data)
}

func TestBreezellRulesFromMemories(t *testing.T) {
	r := newBreezell(t, map[string]string{
		"/home/dev/.breezell/memories/global_rules.md":    "Always run the tests.",
		"/home/dev/.breezell/memories/global_memories.md": "Prefers tabs.",
		"/home/dev/.breezell/memories/notes.json":         "{}",
	}, "/home/dev/.breezell/memories")

	rules, err := r.rules()
	require.NoError(t, err)
	require.Len(t, rules, 2)

	got := map[string]string{}
	for _, x := range rules {
		rule := x.(*mqlBreezellRule)
		got[rule.Name.Data] = rule.Content.Data
		assert.Equal(t, "/home/dev/.breezell/memories/"+rule.Name.Data+".md", rule.Source.Data)
	}
	assert.Equal(t, map[string]string{
		"global_rules":    "Always run the tests.",
		"global_memories": "Prefers tabs.",
	}, got)
}

func TestBreezellUnconfigured(t *testing.T) {
	r := newBreezell(t, nil)

	servers, err := r.mcpServers()
	require.NoError(t, err)
	assert.Empty(t, servers)

	rules, err := r.rules()
	require.NoError(t, err)
	assert.Empty(t, rules)
}
