// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestDiscoveredChildrenInheritTheContextConfig(t *testing.T) {
	cfg := &inventory.ContextConfig{
		Content:   []byte(`{"exceptions":[]}`),
		Origin:    &inventory.ConfigOrigin{Provider: "iac"},
		AssetPath: "k8s/app",
	}
	own := &inventory.ContextConfig{Origin: &inventory.ConfigOrigin{Provider: "github"}}

	parent := &TrackedAsset{
		Asset: &inventory.Asset{Name: "manifest", PlatformIds: []string{"//manifest"}, ContextConfig: cfg},
		State: AssetConnected,
		Runtime: &providers.Runtime{Provider: &providers.ConnectedProvider{Connection: &plugin.ConnectRes{
			Inventory: inventory.New(inventory.WithAssets(
				&inventory.Asset{Name: "deployment", PlatformIds: []string{"//deployment"}},
				&inventory.Asset{Name: "configured", PlatformIds: []string{"//configured"}, ContextConfig: own},
			)),
		}}},
	}
	e := newTestExplorer(parent)
	e.discoverChildren(parent)

	require.Len(t, parent.Children, 2)
	inherited := parent.Children[0].Asset.ContextConfig
	require.NotNil(t, inherited)
	assert.Equal(t, "k8s/app", inherited.AssetPath, "a child sits at its parent's path")
	assert.NotSame(t, cfg, inherited)
	assert.Equal(t, "github", parent.Children[1].Asset.ContextConfig.Origin.Provider, "a child's own config wins")
}
