// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/execruntime"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/inventory/manager"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/utils/slicesx"
)

// ErrDuplicateAsset is returned by Connect when the asset is a duplicate
// of an already-connected asset (detected via platform ID dedup or by the
// coordinator's connection tracking).
var ErrDuplicateAsset = errors.New("duplicate asset")

// AssetState represents the lifecycle state of a tracked asset.
type AssetState int

const (
	// AssetDiscovered means the asset is known but has no active connection.
	AssetDiscovered AssetState = iota
	// AssetConnected means the asset has a live runtime/connection.
	AssetConnected
	// AssetClosed means the asset's connection has been explicitly closed.
	// This is a terminal state — closed assets cannot be reconnected.
	AssetClosed
)

// TrackedAsset holds a discovered asset along with its lifecycle state and
// tree relationships. Callers receive pointers to TrackedAsset and pass them
// back to AssetExplorer methods.
type TrackedAsset struct {
	Asset    *inventory.Asset
	Runtime  *providers.Runtime // nil when Discovered or Closed
	State    AssetState
	Parent   *TrackedAsset   // nil for root assets
	Children []*TrackedAsset // populated when this asset is Connected
}

// Display implements the SelectableItem interface from cli/components,
// allowing TrackedAsset to be used directly with components.Select.
func (t *TrackedAsset) Display() string {
	return t.Asset.HumanName()
}

// AssetExplorerConfig holds configuration for creating a new AssetExplorer.
type AssetExplorerConfig struct {
	Inventory *inventory.Inventory
	Upstream  *upstream.UpstreamConfig
	Recording llx.Recording
}

// AssetExplorer provides lazy, caller-driven asset discovery. It discovers
// one level at a time and lets the caller control which assets to connect
// to and when to release connections.
type AssetExplorer struct {
	mu sync.Mutex

	allAssets []*TrackedAsset

	// seenPlatformIDs records every platform ID encountered during discovery
	// and connection. Enables O(1) child-dedup checks without scanning allAssets,
	// and remains valid after closed assets have their data released.
	seenPlatformIDs map[string]struct{}

	upstream      *upstream.UpstreamConfig
	recording     llx.Recording
	features      []byte
	runtimeLabels map[string]string
	rootAssets    []*inventory.Asset // original root assets, for prepareAsset
	errors        []*AssetWithError
}

// NewAssetExplorer creates an AssetExplorer, connects to the root asset(s) in
// the inventory, and discovers their immediate children. It does NOT recurse
// beyond the first level. Root assets with platform IDs are returned as
// Connected; their children are added as Discovered.
func NewAssetExplorer(ctx context.Context, cfg AssetExplorerConfig) (*AssetExplorer, error) {
	im, err := manager.NewManager(manager.WithInventory(cfg.Inventory, providers.DefaultRuntime()))
	if err != nil {
		return nil, errors.New("failed to resolve inventory for connection: " + err.Error())
	}
	invAssets := im.GetAssets()
	if len(invAssets) == 0 {
		return nil, errors.New("could not find an asset that we can connect to")
	}

	runtimeEnv := execruntime.Detect()
	var runtimeLabels map[string]string
	if runtimeEnv != nil &&
		runtimeEnv.IsAutomatedEnv() &&
		cfg.Inventory.Spec.Assets[0].Category == inventory.AssetCategory_CATEGORY_CICD {
		runtimeLabels = runtimeEnv.Labels()
	}

	e := &AssetExplorer{
		upstream:  cfg.Upstream,
		recording: cfg.Recording,
		// Carry the context's mql features (which include platform/server-activated
		// ones) into every asset connection, unioned with the local
		// cli/config.Features global. Without this, connection-level features
		// present only on the context never reach the provider.
		features:        []byte(mql.GetFeatures(ctx)),
		runtimeLabels:   runtimeLabels,
		seenPlatformIDs: make(map[string]struct{}),
	}

	for _, rootAsset := range invAssets {
		resolvedRootAsset, err := im.ResolveAsset(rootAsset)
		if err != nil {
			return nil, err
		}

		requested := requestedName(resolvedRootAsset)

		awr, err := createRuntimeForAsset(resolvedRootAsset, cfg.Upstream, cfg.Recording, e.features)
		if err != nil {
			log.Error().Err(err).Str("asset", resolvedRootAsset.Name).Msg("unable to create runtime for asset")
			e.errors = append(e.errors, &AssetWithError{Asset: resolvedRootAsset, Err: err})
			continue
		}

		// createRuntimeForAsset reports a duplicate connection as (nil, nil)
		if awr == nil {
			log.Debug().Str("asset", resolvedRootAsset.GetName()).Msg("skipping duplicate root asset")
			continue
		}

		resolvedRootAsset = awr.Asset
		restoreRequestedName(resolvedRootAsset, requested)

		tracked := &TrackedAsset{
			Asset:   resolvedRootAsset,
			Runtime: awr.Runtime,
			State:   AssetConnected,
		}

		if len(resolvedRootAsset.PlatformIds) > 0 {
			prepareAsset(resolvedRootAsset, resolvedRootAsset, runtimeLabels)
		}

		e.allAssets = append(e.allAssets, tracked)
		e.rootAssets = append(e.rootAssets, resolvedRootAsset)
		for _, id := range resolvedRootAsset.PlatformIds {
			e.seenPlatformIDs[id] = struct{}{}
		}

		// Discover immediate children from the root's connection inventory
		e.discoverChildren(tracked)
		handDownRequestedName(tracked, requested)
	}

	return e, nil
}

// Discovered returns all assets in the Discovered state.
func (e *AssetExplorer) Discovered() []*TrackedAsset {
	e.mu.Lock()
	defer e.mu.Unlock()

	var result []*TrackedAsset
	for _, a := range e.allAssets {
		if a.State == AssetDiscovered {
			result = append(result, a)
		}
	}
	return result
}

// Connected returns all assets with live connections.
func (e *AssetExplorer) Connected() []*TrackedAsset {
	e.mu.Lock()
	defer e.mu.Unlock()

	var result []*TrackedAsset
	for _, a := range e.allAssets {
		if a.State == AssetConnected {
			result = append(result, a)
		}
	}
	return result
}

// Connect connects to a tracked asset, creating its runtime and discovering
// its immediate children. Returns the connected asset (whose Children field
// is populated with any newly discovered children).
//
// If the asset is already Connected, this is a no-op returning existing state.
// Closed assets cannot be reconnected — Connect returns an error.
//
// Returns ErrDuplicateAsset if the asset is a duplicate of an already-connected
// asset (either detected by the coordinator or by platform ID dedup). In this
// case the asset's runtime is closed and its state is set to AssetClosed.
func (e *AssetExplorer) Connect(asset *TrackedAsset) (*TrackedAsset, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isKnown(asset) {
		return nil, fmt.Errorf("asset %q is not tracked by this explorer", asset.Asset.GetName())
	}

	if asset.State == AssetConnected {
		return asset, nil
	}

	if asset.State == AssetClosed {
		return nil, fmt.Errorf("asset %q has been closed and cannot be reconnected", asset.Asset.GetName())
	}

	requested := requestedName(asset.Asset)

	awr, err := createRuntimeForAsset(asset.Asset, e.upstream, e.recording, e.features)
	if err != nil {
		e.errors = append(e.errors, &AssetWithError{Asset: asset.Asset, Err: err})
		return nil, err
	}

	// createRuntimeForAsset returns nil when the coordinator detects a duplicate connection
	if awr == nil {
		return nil, fmt.Errorf("asset %q: %w", asset.Asset.GetName(), ErrDuplicateAsset)
	}

	asset.Asset = awr.Asset
	asset.Runtime = awr.Runtime
	asset.State = AssetConnected

	restoreRequestedName(asset.Asset, requested)

	// Run dedup: if this newly connected asset's platform IDs conflict with
	// an already-connected asset, handle subset/superset logic.
	if len(asset.Asset.PlatformIds) > 0 {
		rootAsset := e.findRootAsset(asset)
		prepareAsset(asset.Asset, rootAsset, e.runtimeLabels)
		if e.dedup(asset) {
			return nil, fmt.Errorf("asset %q: %w", asset.Asset.GetName(), ErrDuplicateAsset)
		}
		for _, id := range asset.Asset.PlatformIds {
			e.seenPlatformIDs[id] = struct{}{}
		}
	}

	e.discoverChildren(asset)
	handDownRequestedName(asset, requested)

	return asset, nil
}

// CloseAsset disposes the connection for a specific asset and breaks
// inter-asset reference chains so the GC can reclaim memory from completed
// subtrees. The caller is responsible for closing all connections, including
// gateway assets that were connected just to discover children.
func (e *AssetExplorer) CloseAsset(asset *TrackedAsset) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isKnown(asset) {
		return fmt.Errorf("asset %q is not tracked by this explorer", asset.Asset.GetName())
	}

	if asset.State != AssetConnected {
		return fmt.Errorf("asset %q is not connected (state: %d)", asset.Asset.GetName(), asset.State)
	}

	if asset.Runtime != nil {
		asset.Runtime.Close()
	}
	asset.Runtime = nil
	asset.State = AssetClosed

	// Break bidirectional reference chains between TrackedAsset nodes so
	// completed subtrees become GC-eligible without waiting for the entire
	// scan to finish. seenPlatformIDs preserves dedup state independently.
	asset.Children = nil
	asset.Parent = nil

	return nil
}

// Errors returns all connection/discovery errors encountered so far.
func (e *AssetExplorer) Errors() []*AssetWithError {
	e.mu.Lock()
	defer e.mu.Unlock()

	result := make([]*AssetWithError, len(e.errors))
	copy(result, e.errors)
	return result
}

// Shutdown closes all connected assets and releases all resources.
// After Shutdown the AssetExplorer should not be used.
func (e *AssetExplorer) Shutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, a := range e.allAssets {
		if a.State == AssetConnected {
			if a.Runtime != nil {
				a.Runtime.Close()
			}
			a.Runtime = nil
			a.State = AssetClosed
		}
	}
}

// discoverChildren extracts child assets from a connected asset's inventory
// and adds them as Discovered. Must be called with e.mu held.
func (e *AssetExplorer) discoverChildren(parent *TrackedAsset) {
	if parent.Runtime == nil || parent.Runtime.Provider.Connection == nil {
		return
	}
	inv := parent.Runtime.Provider.Connection.Inventory
	if inv == nil || inv.Spec == nil {
		return
	}

	for _, childAsset := range inv.Spec.Assets {
		// Skip children whose platform IDs are already tracked (simple dedup)
		if len(childAsset.PlatformIds) > 0 && e.hasPlatformID(childAsset.PlatformIds) {
			continue
		}

		child := &TrackedAsset{
			Asset:  childAsset,
			State:  AssetDiscovered,
			Parent: parent,
		}
		e.allAssets = append(e.allAssets, child)
		parent.Children = append(parent.Children, child)
		for _, id := range childAsset.PlatformIds {
			e.seenPlatformIDs[id] = struct{}{}
		}
	}
}

// handDownRequestedName passes a requested asset name to the one asset below a
// node that can actually be scanned.
//
// The fan-out providers connect to an API rather than to a machine: the aws
// provider's detect step sets a platform but never a platform ID, and a node with
// no platform IDs is not scannable and gets dropped. Renaming that node therefore
// changes nothing a user sees -- the asset that gets scanned is a discovered child,
// the account. So when a node cannot be scanned itself and has exactly one child,
// the request belongs to that child. Children are discovered one level at a time,
// so a request that has to travel further down is handed on again when that child
// is connected and its own children appear.
//
// Exactly one child is the whole condition. A node that fans out to many children
// has no single asset the request could mean, and guessing would rename one of a
// fleet after the scan as a whole. This is v12's `len(Assets) == 1` rule, asked one
// level at a time because children are discovered lazily rather than all up front.
//
// Mutates tracked assets, so callers must hold e.mu or otherwise guarantee that
// nothing else can reach the explorer: Connect holds the lock, and the constructor
// runs before the explorer is returned to anyone.
func handDownRequestedName(node *TrackedAsset, requested string) {
	if requested == "" || node == nil {
		return
	}
	if len(node.Asset.GetPlatformIds()) > 0 || len(node.Children) != 1 {
		return
	}

	child := node.Children[0]
	log.Debug().
		Str("discovered", child.Asset.GetName()).
		Str("requested", requested).
		Msg("handing the requested asset name to the only scannable descendant")
	child.Asset.Name = requested
	child.Asset.NameOverride = true
}

// dedup checks if the given asset's platform IDs conflict with any other
// connected asset. Applies subset/superset eviction logic.
// Returns true if the given asset was evicted (closed as a duplicate).
// Must be called with e.mu held.
func (e *AssetExplorer) dedup(asset *TrackedAsset) bool {
	if len(asset.Asset.PlatformIds) == 0 {
		return false
	}

	// Check if the new asset is a subset of an existing asset → evict new
	for _, existing := range e.allAssets {
		if existing == asset || existing.State != AssetConnected {
			continue
		}
		if len(existing.Asset.PlatformIds) == 0 {
			continue
		}
		if slicesx.IsSubsetOf(asset.Asset.PlatformIds, existing.Asset.PlatformIds) {
			log.Debug().Str("asset", asset.Asset.Name).Strs("platform-ids", asset.Asset.PlatformIds).
				Msg("asset-explorer> closing duplicate asset (subset of existing)")
			if asset.Runtime != nil {
				asset.Runtime.Close()
			}
			asset.Runtime = nil
			asset.State = AssetClosed
			return true
		}
	}

	// Evict existing connected assets that are subsets of the new asset
	for _, existing := range e.allAssets {
		if existing == asset || existing.State != AssetConnected {
			continue
		}
		if existing.Asset == nil || len(existing.Asset.PlatformIds) == 0 {
			continue
		}
		if slicesx.IsSubsetOf(existing.Asset.PlatformIds, asset.Asset.PlatformIds) {
			log.Debug().Str("asset", existing.Asset.Name).Strs("platform-ids", existing.Asset.PlatformIds).
				Msg("asset-explorer> evicting asset (subset of new asset)")
			if existing.Runtime != nil {
				existing.Runtime.Close()
			}
			existing.Runtime = nil
			existing.State = AssetClosed
			existing.Children = nil
			existing.Parent = nil
		}
	}
	return false
}

// isKnown returns true if the given TrackedAsset pointer is tracked by this explorer.
// Must be called with e.mu held.
func (e *AssetExplorer) isKnown(asset *TrackedAsset) bool {
	return slices.Contains(e.allAssets, asset)
}

// hasPlatformID returns true if any of the given platform IDs have already
// been seen (discovered or connected). Uses the seenPlatformIDs index for
// O(1) lookups instead of scanning allAssets. Must be called with e.mu held.
func (e *AssetExplorer) hasPlatformID(ids []string) bool {
	for _, id := range ids {
		if _, ok := e.seenPlatformIDs[id]; ok {
			return true
		}
	}
	return false
}

// findRootAsset walks up the parent chain to find the root asset for
// prepareAsset labeling. Must be called with e.mu held.
func (e *AssetExplorer) findRootAsset(asset *TrackedAsset) *inventory.Asset {
	current := asset
	for current.Parent != nil {
		current = current.Parent
	}
	return current.Asset
}
