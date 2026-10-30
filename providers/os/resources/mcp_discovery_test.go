// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestMcpConnectionConfig verifies that discovery emits how to start the server
// (protocol + target) and, crucially, never the server's env/secrets — those are
// supplied explicitly at connect time via the AI provider's `--env`. See ADR 030.
func TestMcpConnectionConfig(t *testing.T) {
	t.Run("stdio emits protocol+target and no env", func(t *testing.T) {
		srv := &mqlClaudeCodeMcpServer{
			Type:    plugin.TValue[string]{Data: "stdio", State: plugin.StateIsSet},
			Command: plugin.TValue[string]{Data: "npx", State: plugin.StateIsSet},
			Args:    plugin.TValue[[]any]{Data: []any{"-y", "@scope/server", "run"}, State: plugin.StateIsSet},
		}

		conf := mcpConnectionConfig(srv)
		require.NotNil(t, conf)
		assert.Equal(t, "mcp", conf.Type)
		assert.Equal(t, "stdio", conf.Options["protocol"])
		assert.Equal(t, "npx -y @scope/server run", conf.Options["target"])
		_, hasEnv := conf.Options["env"]
		assert.False(t, hasEnv, "discovery must not carry env/secrets")
	})

	t.Run("http server uses url target", func(t *testing.T) {
		srv := &mqlClaudeCodeMcpServer{
			Type: plugin.TValue[string]{Data: "http", State: plugin.StateIsSet},
			Url:  plugin.TValue[string]{Data: "https://mcp.example.com/mcp", State: plugin.StateIsSet},
		}
		conf := mcpConnectionConfig(srv)
		require.NotNil(t, conf)
		assert.Equal(t, "https", conf.Options["protocol"])
		assert.Equal(t, "https://mcp.example.com/mcp", conf.Options["target"])
	})

	t.Run("sse server is a remote transport, not dropped", func(t *testing.T) {
		// Cursor remote servers declare `type: "sse"`; it is URL-based like http,
		// so discovery must emit it rather than silently drop it. See ADR 030.
		srv := &mqlClaudeCodeMcpServer{
			Type: plugin.TValue[string]{Data: "sse", State: plugin.StateIsSet},
			Url:  plugin.TValue[string]{Data: "https://mcp.example.com/sse", State: plugin.StateIsSet},
		}
		conf := mcpConnectionConfig(srv)
		require.NotNil(t, conf)
		assert.Equal(t, "https", conf.Options["protocol"])
		assert.Equal(t, "https://mcp.example.com/sse", conf.Options["target"])
	})

	t.Run("transport type is matched case-insensitively", func(t *testing.T) {
		// A config that spells the type in any case must still be recognized as
		// stdio rather than falling through to the URL branch and being dropped.
		srv := &mqlClaudeCodeMcpServer{
			Type:    plugin.TValue[string]{Data: "STDIO", State: plugin.StateIsSet},
			Command: plugin.TValue[string]{Data: "npx", State: plugin.StateIsSet},
		}
		conf := mcpConnectionConfig(srv)
		require.NotNil(t, conf)
		assert.Equal(t, "stdio", conf.Options["protocol"])
		assert.Equal(t, "npx", conf.Options["target"])
	})
}

// The asset a query resolves into and the asset a scan would have discovered
// have to be the same asset, not merely similar ones: the anchor is what joins
// them, and a drift there means a cross-asset query connects to something the
// scan never saw. They share one constructor, and this is what holds them to it.
func TestMcpServerAssetMatchesDiscovery(t *testing.T) {
	srv := &mqlClaudeCodeMcpServer{
		Name:    plugin.TValue[string]{Data: "github", State: plugin.StateIsSet},
		Type:    plugin.TValue[string]{Data: "stdio", State: plugin.StateIsSet},
		Command: plugin.TValue[string]{Data: "npx", State: plugin.StateIsSet},
		Args:    plugin.TValue[[]any]{Data: []any{"-y", "@modelcontextprotocol/server-github"}, State: plugin.StateIsSet},
	}
	host := &inventory.Asset{
		Id:          "host-id",
		Mrn:         "//assets/host",
		PlatformIds: []string{"//platformid/host"},
		Name:        "should-not-travel",
	}

	// What discovery emits, and what `running` resolves to, for the same server.
	discovered := mcpServerAssetWith(srv, mcpConnectionConfig(srv), hostRefOf(host))
	require.NotNil(t, discovered)

	assert.Equal(t, "github", discovered.Name)
	require.Len(t, discovered.Connections, 1)
	assert.Equal(t, "mcp", discovered.Connections[0].Type)
	assert.Equal(t, "npx -y @modelcontextprotocol/server-github", discovered.Connections[0].Options["target"])

	// The anchor is the server resource's own (type, id) - the same pair the
	// `running` value carries, which is what lets the host join the two.
	require.Len(t, discovered.Relationships, 1)
	rel := discovered.Relationships[0]
	assert.Equal(t, srv.MqlName(), rel.ResourceType)
	assert.Equal(t, srv.MqlID(), rel.ResourceId)

	anchor := mcpServerAsset(srv)
	assert.Equal(t, anchor.ResourceType, rel.ResourceType)
	assert.Equal(t, anchor.ResourceId, rel.ResourceId)

	// The parent is referenced by identity only.
	require.NotNil(t, rel.Asset)
	assert.Equal(t, "//assets/host", rel.Asset.Mrn)
	assert.Equal(t, []string{"//platformid/host"}, rel.Asset.PlatformIds)
	assert.Empty(t, rel.Asset.Name, "a host reference carries identity, not display data")
}

// A server config with neither a command nor a url has nothing to connect to.
// That is a half-written config, not an error, and it must not produce an asset
// with an empty connection that fails later with nothing to attribute it to.
func TestMcpServerAssetWithoutATarget(t *testing.T) {
	srv := &mqlClaudeCodeMcpServer{
		Name: plugin.TValue[string]{Data: "broken", State: plugin.StateIsSet},
	}

	assert.Nil(t, mcpConnectionConfig(srv))

	asset, err := mcpServerAssetFor(&plugin.Runtime{}, srv)
	require.NoError(t, err)
	assert.Nil(t, asset)
}
