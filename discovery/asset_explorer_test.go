// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/providers"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestMergeConnectionFeatures verifies that connection features are the union of
// the local cli/config.Features global and caller-supplied (server-activated)
// features — so a feature present only on the context (e.g. one activated
// upstream and returned by GetScanParameters) still reaches the provider
// connection.
func TestMergeConnectionFeatures(t *testing.T) {
	saved := config.Features
	t.Cleanup(func() { config.Features = saved })
	config.Features = []byte{7, 9} // local config features

	t.Run("adds server features on top of local ones", func(t *testing.T) {
		got := mergeConnectionFeatures([]byte{17}) // server-activated feature
		assert.ElementsMatch(t, []byte{7, 9, 17}, got)
	})

	t.Run("deduplicates overlap", func(t *testing.T) {
		got := mergeConnectionFeatures([]byte{9, 17})
		assert.ElementsMatch(t, []byte{7, 9, 17}, got)
	})

	t.Run("nil extra returns just the local features", func(t *testing.T) {
		got := mergeConnectionFeatures(nil)
		assert.ElementsMatch(t, []byte{7, 9}, got)
	})
}

func newTestExplorer(assets ...*TrackedAsset) *AssetExplorer {
	seen := make(map[string]struct{})
	for _, a := range assets {
		if a.Asset != nil {
			for _, id := range a.Asset.PlatformIds {
				seen[id] = struct{}{}
			}
		}
	}
	return &AssetExplorer{
		allAssets:       assets,
		seenPlatformIDs: seen,
	}
}

func TestAssetExplorerDiscovered(t *testing.T) {
	discovered := &TrackedAsset{
		Asset: &inventory.Asset{Name: "child1"},
		State: AssetDiscovered,
	}
	connected := &TrackedAsset{
		Asset: &inventory.Asset{Name: "root"},
		State: AssetConnected,
	}
	closed := &TrackedAsset{
		Asset: &inventory.Asset{Name: "old"},
		State: AssetClosed,
	}

	e := newTestExplorer(discovered, connected, closed)
	result := e.Discovered()
	assert.Len(t, result, 1)
	assert.Equal(t, "child1", result[0].Asset.Name)
}

func TestAssetExplorerConnected(t *testing.T) {
	discovered := &TrackedAsset{
		Asset: &inventory.Asset{Name: "child1"},
		State: AssetDiscovered,
	}
	connected := &TrackedAsset{
		Asset: &inventory.Asset{Name: "root"},
		State: AssetConnected,
	}

	e := newTestExplorer(discovered, connected)
	result := e.Connected()
	assert.Len(t, result, 1)
	assert.Equal(t, "root", result[0].Asset.Name)
}

func TestAssetExplorerCloseAsset(t *testing.T) {
	t.Run("close connected asset", func(t *testing.T) {
		child := &TrackedAsset{
			Asset: &inventory.Asset{Name: "child"},
			State: AssetDiscovered,
		}
		parent := &TrackedAsset{
			Asset: &inventory.Asset{Name: "parent"},
			State: AssetConnected,
		}
		asset := &TrackedAsset{
			Asset:    &inventory.Asset{Name: "root"},
			State:    AssetConnected,
			Parent:   parent,
			Children: []*TrackedAsset{child},
			// Runtime is nil in tests since we don't have a real provider
		}
		e := newTestExplorer(asset, parent, child)

		err := e.CloseAsset(asset)
		require.NoError(t, err)
		assert.Equal(t, AssetClosed, asset.State)
		assert.Nil(t, asset.Runtime)
		assert.Nil(t, asset.Children, "Children should be nil'd to break reference chains")
		assert.Nil(t, asset.Parent, "Parent should be nil'd to break reference chains")
	})

	t.Run("close discovered asset fails", func(t *testing.T) {
		asset := &TrackedAsset{
			Asset: &inventory.Asset{Name: "child"},
			State: AssetDiscovered,
		}
		e := newTestExplorer(asset)

		err := e.CloseAsset(asset)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not connected")
	})

	t.Run("close unknown asset fails", func(t *testing.T) {
		e := newTestExplorer()
		unknown := &TrackedAsset{
			Asset: &inventory.Asset{Name: "unknown"},
			State: AssetConnected,
		}

		err := e.CloseAsset(unknown)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not tracked")
	})
}

func TestAssetExplorerShutdown(t *testing.T) {
	connected1 := &TrackedAsset{
		Asset: &inventory.Asset{Name: "a"},
		State: AssetConnected,
	}
	connected2 := &TrackedAsset{
		Asset: &inventory.Asset{Name: "b"},
		State: AssetConnected,
	}
	discovered := &TrackedAsset{
		Asset: &inventory.Asset{Name: "c"},
		State: AssetDiscovered,
	}

	e := newTestExplorer(connected1, connected2, discovered)
	e.Shutdown()

	assert.Equal(t, AssetClosed, connected1.State)
	assert.Equal(t, AssetClosed, connected2.State)
	assert.Equal(t, AssetDiscovered, discovered.State) // unchanged
}

func TestAssetExplorerConnectAlreadyConnected(t *testing.T) {
	child1 := &TrackedAsset{
		Asset: &inventory.Asset{Name: "child1"},
		State: AssetDiscovered,
	}
	parent := &TrackedAsset{
		Asset:    &inventory.Asset{Name: "root", PlatformIds: []string{"id/1"}},
		State:    AssetConnected,
		Children: []*TrackedAsset{child1},
	}

	e := newTestExplorer(parent, child1)
	connected, err := e.Connect(parent)
	require.NoError(t, err)
	assert.Equal(t, parent, connected)
	assert.Len(t, connected.Children, 1)
	assert.Equal(t, "child1", connected.Children[0].Asset.Name)
}

func TestAssetExplorerConnectClosedAsset(t *testing.T) {
	asset := &TrackedAsset{
		Asset: &inventory.Asset{Name: "closed"},
		State: AssetClosed,
	}
	e := newTestExplorer(asset)

	_, err := e.Connect(asset)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestAssetExplorerConnectUnknownAsset(t *testing.T) {
	e := newTestExplorer()
	unknown := &TrackedAsset{
		Asset: &inventory.Asset{Name: "unknown"},
		State: AssetDiscovered,
	}

	_, err := e.Connect(unknown)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not tracked")
}

func TestAssetExplorerDedup(t *testing.T) {
	t.Run("new asset that is subset of existing gets closed", func(t *testing.T) {
		existing := &TrackedAsset{
			Asset: &inventory.Asset{Name: "big", PlatformIds: []string{"id/1", "id/2", "id/3"}},
			State: AssetConnected,
		}
		newAsset := &TrackedAsset{
			Asset: &inventory.Asset{Name: "small", PlatformIds: []string{"id/1", "id/2"}},
			State: AssetConnected,
		}

		e := newTestExplorer(existing, newAsset)
		e.dedup(newAsset)

		assert.Equal(t, AssetClosed, newAsset.State)
		assert.Equal(t, AssetConnected, existing.State)
	})

	t.Run("existing asset that is subset of new gets evicted", func(t *testing.T) {
		child := &TrackedAsset{
			Asset: &inventory.Asset{Name: "leaf"},
			State: AssetDiscovered,
		}
		existing := &TrackedAsset{
			Asset:    &inventory.Asset{Name: "small", PlatformIds: []string{"id/1"}},
			State:    AssetConnected,
			Children: []*TrackedAsset{child},
		}
		newAsset := &TrackedAsset{
			Asset: &inventory.Asset{Name: "big", PlatformIds: []string{"id/1", "id/2"}},
			State: AssetConnected,
		}

		e := newTestExplorer(existing, newAsset)
		e.dedup(newAsset)

		assert.Equal(t, AssetClosed, existing.State)
		assert.Nil(t, existing.Children, "evicted asset Children should be nil'd")
		assert.Nil(t, existing.Parent, "evicted asset Parent should be nil'd")
		assert.Equal(t, AssetConnected, newAsset.State)
	})

	t.Run("unrelated assets coexist", func(t *testing.T) {
		a := &TrackedAsset{
			Asset: &inventory.Asset{Name: "a", PlatformIds: []string{"id/1"}},
			State: AssetConnected,
		}
		b := &TrackedAsset{
			Asset: &inventory.Asset{Name: "b", PlatformIds: []string{"id/2"}},
			State: AssetConnected,
		}

		e := newTestExplorer(a, b)
		e.dedup(b)

		assert.Equal(t, AssetConnected, a.State)
		assert.Equal(t, AssetConnected, b.State)
	})

	t.Run("assets with no platform IDs are skipped", func(t *testing.T) {
		a := &TrackedAsset{
			Asset: &inventory.Asset{Name: "gateway"},
			State: AssetConnected,
		}

		e := newTestExplorer(a)
		e.dedup(a) // should not panic or change state

		assert.Equal(t, AssetConnected, a.State)
	})
}

func TestAssetExplorerHasPlatformID(t *testing.T) {
	a := &TrackedAsset{
		Asset: &inventory.Asset{Name: "a", PlatformIds: []string{"id/1", "id/2"}},
		State: AssetConnected,
	}
	e := newTestExplorer(a)

	assert.True(t, e.hasPlatformID([]string{"id/1"}))
	assert.True(t, e.hasPlatformID([]string{"id/2"}))
	assert.True(t, e.hasPlatformID([]string{"id/3", "id/1"}))
	assert.False(t, e.hasPlatformID([]string{"id/3"}))
	assert.False(t, e.hasPlatformID(nil))
}

func TestAssetExplorerErrors(t *testing.T) {
	e := newTestExplorer()
	e.errors = []*AssetWithError{
		{Asset: &inventory.Asset{Name: "bad"}, Err: assert.AnError},
	}

	errs := e.Errors()
	assert.Len(t, errs, 1)
	assert.Equal(t, "bad", errs[0].Asset.Name)
}

func TestTrackedAssetParentChain(t *testing.T) {
	root := &TrackedAsset{
		Asset: &inventory.Asset{Name: "root", PlatformIds: []string{"root/1"}},
		State: AssetConnected,
	}
	mid := &TrackedAsset{
		Asset:  &inventory.Asset{Name: "mid"},
		State:  AssetConnected,
		Parent: root,
	}
	leaf := &TrackedAsset{
		Asset:  &inventory.Asset{Name: "leaf"},
		State:  AssetDiscovered,
		Parent: mid,
	}

	e := newTestExplorer(root, mid, leaf)
	foundRoot := e.findRootAsset(leaf)
	assert.Equal(t, "root", foundRoot.Name)
}

// gatewayWithChildren is a connected asset whose connection reported children,
// as a repository-discovering provider does.
func gatewayWithChildren(children ...*inventory.Asset) *TrackedAsset {
	return &TrackedAsset{
		Asset: &inventory.Asset{Name: "gateway"},
		State: AssetConnected,
		Runtime: &providers.Runtime{
			Provider: &providers.ConnectedProvider{
				Connection: &plugin.ConnectRes{
					Inventory: &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: children}},
				},
			},
		},
	}
}

// A provider presets Name and PlatformIds on the children it discovers. The
// explorer must track those very assets, with their presets intact, and treat a
// repeated preset id as a duplicate.
func TestAssetExplorerDiscoverChildrenHonorsPresetIdentity(t *testing.T) {
	const (
		idA = "//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/fabrikam-fixture-org/project/scan-test/repo/ado-scan-test-iac"
		idB = "//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/fabrikam-other-fixture-org/project/scan-test/repo/ado-scan-test-iac"
	)
	childA := &inventory.Asset{Name: "scan-test/ado-scan-test-iac", PlatformIds: []string{idA}}
	childB := &inventory.Asset{Name: "scan-test/ado-scan-test-iac", PlatformIds: []string{idB}}
	again := &inventory.Asset{Name: "scan-test/ado-scan-test-iac", PlatformIds: []string{idA}}

	gateway := gatewayWithChildren(childA, childB, again)
	e := newTestExplorer(gateway)

	e.discoverChildren(gateway)

	require.Len(t, gateway.Children, 2, "two organizations, one repository name: two assets; the repeated id is dropped")
	assert.Same(t, childA, gateway.Children[0].Asset, "the preset asset itself is tracked, not a copy")
	assert.Same(t, childB, gateway.Children[1].Asset)
	assert.Equal(t, []string{idA}, gateway.Children[0].Asset.PlatformIds)
	assert.Equal(t, []string{idB}, gateway.Children[1].Asset.PlatformIds)
	assert.Equal(t, "scan-test/ado-scan-test-iac", gateway.Children[0].Asset.Name)
	for _, child := range gateway.Children {
		assert.Equal(t, AssetDiscovered, child.State)
		assert.Same(t, gateway, child.Parent)
	}
	assert.True(t, e.hasPlatformID([]string{idA}), "preset ids feed the dedup index")
	assert.True(t, e.hasPlatformID([]string{idB}))
	assert.Len(t, e.allAssets, 3, "the gateway and its two children")
}
