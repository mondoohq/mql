// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevinCLIVersionFromLink(t *testing.T) {
	// install.sh: ln -s "$VERSION" "$CURRENT_LINK", a relative target.
	assert.Equal(t, "3000.11.205", devinCLIVersionFromLink("3000.11.205"))
	assert.Equal(t, "3000.11.205", devinCLIVersionFromLink("/home/alice/.local/share/devin/cli/_versions/3000.11.205"))
	assert.Equal(t, "", devinCLIVersionFromLink(""))
	assert.Equal(t, "", devinCLIVersionFromLink("not-a-version"))
}

func TestCursorCLIVersionFromLink(t *testing.T) {
	// install script: ln -s ~/.local/share/cursor-agent/versions/<ver>/cursor-agent ~/.local/bin/cursor-agent
	assert.Equal(t, "2026.10.22-27dcf5f",
		cursorCLIVersionFromLink("/Users/alice/.local/share/cursor-agent/versions/2026.10.22-27dcf5f/cursor-agent"))
	assert.Equal(t, "", cursorCLIVersionFromLink("/opt/homebrew/Caskroom/cursor-cli/2026.10.22-27dcf5f/dist-package/cursor-agent"))
	assert.Equal(t, "", cursorCLIVersionFromLink(""))
}

func TestParseCursorCLIConfig(t *testing.T) {
	cfg, err := parseCursorCLIConfig([]byte(`{
  "version": 1,
  "editor": { "vimMode": false },
  "approvalMode": "allowlist",
  "sandbox": { "mode": "enabled", "networkAccess": "allowlist" },
  "permissions": {
    "allow": ["Shell(ls)", "Shell(echo)"],
    "deny": ["Shell(rm)"]
  }
}`))
	require.NoError(t, err)
	assert.Equal(t, "allowlist", cfg.ApprovalMode)
	assert.Equal(t, "enabled", cfg.Sandbox.Mode)
	assert.Equal(t, "allowlist", rawSetting(cfg.Sandbox.NetworkAccess))
	assert.Equal(t, []string{"Shell(ls)", "Shell(echo)"}, cfg.Permissions.Allow)
	assert.Equal(t, []string{"Shell(rm)"}, cfg.Permissions.Deny)

	// A setting of another JSON type is kept as written, not a parse failure.
	cfg, err = parseCursorCLIConfig([]byte(`{"sandbox": {"networkAccess": true}}`))
	require.NoError(t, err)
	assert.Equal(t, "true", rawSetting(cfg.Sandbox.NetworkAccess))

	cfg, err = parseCursorCLIConfig(nil)
	require.NoError(t, err)
	assert.Empty(t, cfg.ApprovalMode)
}

func TestParseDshPatchMcpServers(t *testing.T) {
	// The shape of the harness's own examples (apps/cli/config/examples/mcp-memory
	// and docs/user/guide/mcp-memory.md), including the !!js tag it evaluates.
	specs, err := parseDshPatchMcpServers([]byte(`
# Opt-in reference for Memorix.
- insert:
    - id: memory-memorix
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: memorix
        transport: stdio
        command: memorix
        args: [serve]
        env:
          MEMORIX_DATA_DIR: /data
        cwd: !!js process.cwd()
    - id: some-other-plugin
      name: '@deepseek-ai/dsh-skill-office'
      config: {}
- insert:
    - id: remote
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: docs
        transport: streamable-http
        url: https://example.com/mcp
        headers:
          Authorization: Bearer x
- remove:
    - id: something
`), "/home/alice/.dsh/cordis.patch.yml")
	require.NoError(t, err)
	require.Len(t, specs, 2)

	assert.Equal(t, "docs", specs[0].name)
	assert.Equal(t, mcpTransportHTTP, specs[0].transport)
	assert.Equal(t, "https://example.com/mcp", specs[0].url)
	assert.True(t, specs[0].hasHeaders)
	assert.False(t, specs[0].hasEnv)

	assert.Equal(t, "memorix", specs[1].name)
	assert.Equal(t, mcpTransportStdio, specs[1].transport)
	assert.Equal(t, "memorix", specs[1].command)
	assert.Equal(t, []string{"serve"}, specs[1].args)
	assert.True(t, specs[1].hasEnv)
	assert.True(t, specs[1].enabled)
	assert.Equal(t, "/home/alice/.dsh/cordis.patch.yml", specs[1].source)

	assert.Nil(t, yamlScalars(nil))
	assert.False(t, yamlNonEmpty(nil))

	specs, err = parseDshPatchMcpServers(nil, "empty")
	require.NoError(t, err)
	assert.Empty(t, specs)
}

func TestDevinCLIMcpConfig(t *testing.T) {
	// docs.devin.ai/cli/extensibility/mcp/configuration: url servers carry a
	// transport, and disabled switches a server off.
	specs, err := parseMcpServersJSON([]byte(`{"mcpServers": {
  "notion": {"url": "https://mcp.notion.com/mcp", "transport": "http"},
  "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "x"}, "disabled": true}
}}`), "mcpServers", "mcp_config.json")
	require.NoError(t, err)
	require.Len(t, specs, 2)
	assert.Equal(t, "github", specs[0].name)
	assert.Equal(t, mcpTransportStdio, specs[0].transport)
	assert.False(t, specs[0].enabled)
	assert.True(t, specs[0].hasEnv)
	assert.Equal(t, "notion", specs[1].name)
	assert.Equal(t, "http", specs[1].transport)
	assert.Equal(t, "https://mcp.notion.com/mcp", specs[1].url)
}

func TestCLIToolPackageSpecs(t *testing.T) {
	assert.True(t, toolPackageSpecs["devin.cli"].configShared, "Devin Desktop shares ~/.config/devin")
	assert.True(t, toolPackageSpecs["cursor.cli"].configIsFile, "cli-config.json is a file the editor never writes")
	assert.NotContains(t, toolPackageSpecs["cursor.cli"].homeBinaries, ".local/bin/agent", "bare agent is too generic")
	assert.Contains(t, mcpClientResources, "devin.cli")
	assert.Contains(t, mcpClientResources, "deepseek.harness")
}
