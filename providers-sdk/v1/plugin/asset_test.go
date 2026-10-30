// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/utils/syncx"
)

type assetResource struct {
	name  string
	id    string
	asset *inventory.Asset
	err   error
}

func (a *assetResource) MqlName() string { return a.name }
func (a *assetResource) MqlID() string   { return a.id }
func (a *assetResource) MqlAsset() (*inventory.Asset, error) {
	return a.asset, a.err
}

type plainResource struct{ name, id string }

func (p *plainResource) MqlName() string { return p.name }
func (p *plainResource) MqlID() string   { return p.id }

func serviceWith(t *testing.T, resources ...Resource) *Service {
	t.Helper()
	s := &Service{runtimes: map[uint32]*Runtime{}}
	runtime := &Runtime{Resources: &syncx.Map[Resource]{}}
	for _, r := range resources {
		runtime.Resources.Set(r.MqlName()+"\x00"+r.MqlID(), r)
	}
	s.addRuntime(1, runtime)
	return s
}

// Every provider inherits this, so a provider whose resources implement
// AssetSource needs no code of its own to answer (ADR 031 phase 8).
func TestServiceResolveAsset(t *testing.T) {
	want := &inventory.Asset{
		Name:        "github-mcp",
		Connections: []*inventory.Config{{Type: "mcp"}},
	}
	source := &assetResource{name: "claude.code.mcpServer", id: "srv/github", asset: want}
	plain := &plainResource{name: "sshd.config", id: "sshd.config"}

	t.Run("answers from the resource", func(t *testing.T) {
		s := serviceWith(t, source, plain)

		res, err := s.ResolveAsset(&ResolveAssetReq{
			Connection: 1, ResourceType: source.name, ResourceId: source.id,
		})
		require.NoError(t, err)
		require.NotNil(t, res.Asset)
		assert.Equal(t, "github-mcp", res.Asset.Name)
		assert.Equal(t, "mcp", res.Asset.Connections[0].Type)
	})

	// Most resources are not assets, and most anchors will not be found. Both
	// are ordinary states, so both answer with no asset rather than an error -
	// the caller is the one that knows whether it needed one.
	t.Run("a resource that is not an asset source", func(t *testing.T) {
		s := serviceWith(t, source, plain)

		res, err := s.ResolveAsset(&ResolveAssetReq{
			Connection: 1, ResourceType: plain.name, ResourceId: plain.id,
		})
		require.NoError(t, err)
		assert.Nil(t, res.Asset)
	})

	t.Run("an anchor this connection does not hold", func(t *testing.T) {
		s := serviceWith(t, source)

		res, err := s.ResolveAsset(&ResolveAssetReq{
			Connection: 1, ResourceType: source.name, ResourceId: "srv/nope",
		})
		require.NoError(t, err)
		assert.Nil(t, res.Asset)
	})

	// A resource with nothing to connect to - an MCP server config carrying
	// neither a command nor a url - is a half-written config, not a failure.
	t.Run("an asset source with nothing to connect to", func(t *testing.T) {
		empty := &assetResource{name: "claude.code.mcpServer", id: "srv/empty"}
		s := serviceWith(t, empty)

		res, err := s.ResolveAsset(&ResolveAssetReq{
			Connection: 1, ResourceType: empty.name, ResourceId: empty.id,
		})
		require.NoError(t, err)
		assert.Nil(t, res.Asset)
	})

	// A failure to build the asset is a real error and must not read as "there
	// is nothing here", which would silently skip the target.
	t.Run("a failure to build the asset", func(t *testing.T) {
		broken := &assetResource{name: "claude.code.mcpServer", id: "srv/broken", err: errors.New("config unreadable")}
		s := serviceWith(t, broken)

		_, err := s.ResolveAsset(&ResolveAssetReq{
			Connection: 1, ResourceType: broken.name, ResourceId: broken.id,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config unreadable")
	})

	t.Run("an unknown connection", func(t *testing.T) {
		s := serviceWith(t, source)

		_, err := s.ResolveAsset(&ResolveAssetReq{
			Connection: 99, ResourceType: source.name, ResourceId: source.id,
		})
		assert.Error(t, err)
	})
}
