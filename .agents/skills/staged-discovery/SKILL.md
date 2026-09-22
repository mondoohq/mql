---
name: staged-discovery
description: Add staged discovery support to a provider. Use when the user wants to implement staged/phased discovery, break down discovery into stages, add OptionStagedDiscovery support, or optimize a provider's memory usage during discovery. Triggers on requests like "add staged discovery to gcp", "implement staged discovery for aws", "break down discovery for <provider>", or "optimize <provider> discovery".
argument-hint: "<provider-name> (e.g., aws, gcp, k8s, azure)"
---

# Add Staged Discovery to a Provider

Implement staged (multi-phase) discovery for a provider so that `AssetExplorer` can traverse the provider's resource hierarchy one level at a time, releasing memory after each scope is closed.

**Background:** See `docs/adr/002-staged-discovery.md` for the full design rationale and `docs/adr/001-asset-explorer-lazy-discovery.md` for how `AssetExplorer` drives the traversal.

**Reference implementation:** The K8s provider in `providers/k8s/resources/discovery.go` — study `Discover()`, `discoverClusterStage()`, and `discoverNamespaceStage()` as the canonical example.

## Prerequisites

Before starting, understand the provider's resource hierarchy. Every provider has a natural tree:
- **K8s:** cluster → namespaces → workloads (pods, deployments, etc.)
- **GCP:** organization → projects → services → resources
- **AWS:** organization → accounts → regions → resources
- **Azure:** tenant → subscriptions → resource groups → resources

Each level of this tree becomes a discovery stage. Ask the user to confirm the hierarchy if it's not obvious.

## Step-by-Step Implementation

### Step 1: Identify the discovery entry point

Find the provider's `Discover()` function. It is typically in `providers/<name>/resources/discovery.go` or called from `providers/<name>/provider/provider.go` during connection setup.

```bash
# Find the discovery function
grep -rn "func.*Discover" providers/<name>/resources/ providers/<name>/provider/
```

Read the existing discovery logic thoroughly. Understand:
- What assets are currently returned (the full set)
- How platform IDs are constructed
- How connection configs are set on child assets
- Whether `WithParentConnectionId` is used and where

### Step 2: Add the staged discovery router

Modify the `Discover()` function to check for `OptionStagedDiscovery` and route to stage-specific functions. The legacy path MUST remain unchanged — older clients that don't set the flag must continue working.

```go
import "go.mondoo.com/mql/providers-sdk/v1/plugin"

func Discover(runtime *plugin.Runtime, ...) (*inventory.Inventory, error) {
    conn := runtime.Connection.(YourConnection)
    invConfig := conn.InventoryConfig()

    if _, ok := invConfig.Options[plugin.OptionStagedDiscovery]; ok {
        // Route based on which stage we're in.
        // Use a provider-specific option to determine the current scope.
        if invConfig.Options["your-scope-option"] != "" {
            return discoverScopedStage(runtime, conn, invConfig)
        }
        return discoverRootStage(runtime, conn, invConfig)
    }

    // Legacy single-pass discovery — DO NOT MODIFY
    // TODO(v15): remove this once all clients use staged discovery
    return discoverLegacy(runtime, conn, invConfig)
}
```

**Important:** Rename the existing discovery function to `discoverLegacy` (or similar) and add a `TODO(v15)` comment. Do not delete it.

### Step 3: Implement Stage 1 (root/top-level scope)

Stage 1 discovers the top-level asset and its immediate children. Children are returned as assets with connection configs that trigger Stage 2 when connected.

**Critical rules:**
- Child assets that represent a new scope (e.g., namespaces, projects, regions) must NOT use `WithParentConnectionId`. They need their own independent runtime so their MQL resource cache is isolated and released when the scope is closed.
- Clone the parent's connection config for each child, adding a scope option that identifies the next stage.
- The `OptionStagedDiscovery` flag is propagated automatically by `Clone()`.

```go
func discoverRootStage(runtime *plugin.Runtime, conn YourConnection, invConfig *inventory.Config) (*inventory.Inventory, error) {
    in := &inventory.Inventory{Spec: &inventory.InventorySpec{
        Assets: []*inventory.Asset{},
    }}

    // 1. Discover the root asset itself (with platform IDs)
    rootAsset := &inventory.Asset{
        PlatformIds: []string{rootPlatformId},
        Name:        conn.Name(),
        Platform:    conn.Platform(),
        Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery())},
    }
    in.Spec.Assets = append(in.Spec.Assets, rootAsset)

    // 2. Discover child scopes (e.g., projects, namespaces, regions)
    children, err := listChildScopes(conn)
    if err != nil {
        return nil, err
    }

    for _, child := range children {
        // Clone WITHOUT WithParentConnectionId — each child gets its own
        // runtime and MQL resource cache, released when the child is closed.
        childConfig := invConfig.Clone()
        childConfig.Options["your-scope-option"] = child.ID

        childAsset := &inventory.Asset{
            PlatformIds: []string{child.PlatformId},
            Name:        child.Name,
            Platform:    child.Platform,
            Connections: []*inventory.Config{childConfig},
        }
        in.Spec.Assets = append(in.Spec.Assets, childAsset)
    }

    return in, nil
}
```

### Step 4: Implement Stage 2+ (scoped discovery)

Each subsequent stage reads its scope from the connection config, discovers resources within that scope, and optionally emits further children for deeper stages.

**Leaf assets within a scope SHOULD use `WithParentConnectionId`** to share the scope's API client cache. This avoids redundant API calls while keeping the cache scoped to the parent (not the root).

```go
func discoverScopedStage(runtime *plugin.Runtime, conn YourConnection, invConfig *inventory.Config) (*inventory.Inventory, error) {
    scopeId := invConfig.Options["your-scope-option"]

    in := &inventory.Inventory{Spec: &inventory.InventorySpec{
        Assets: []*inventory.Asset{},
    }}

    // Discover resources within this scope
    resources, err := listResourcesInScope(conn, scopeId)
    if err != nil {
        return nil, err
    }

    for _, res := range resources {
        resAsset := &inventory.Asset{
            PlatformIds: []string{res.PlatformId},
            Name:        res.Name,
            Platform:    res.Platform,
            // Leaf assets share the scope's API cache
            Connections: []*inventory.Config{invConfig.Clone(
                inventory.WithParentConnectionId(invConfig.Id),
            )},
        }
        in.Spec.Assets = append(in.Spec.Assets, resAsset)
    }

    return in, nil
}
```

### Step 5: Strip platform IDs from non-targeted intermediate assets

When users specify discovery targets (e.g., `--discover pods`), intermediate assets that don't match the targets must still be emitted (so `AssetExplorer` connects to them and discovers their children), but should NOT be scanned. The simplest way: **strip their platform IDs**. The existing "no platform IDs → skip" logic in `AssetExplorer` and the scanner already handles this — no caller-side changes needed.

```go
// In your root stage, when emitting child scope assets:
isScopeTargeted := isTargeted(invConfig.Discover.Targets, YourScopeDiscoveryTarget)

for _, child := range children {
    childConfig := invConfig.Clone()
    childConfig.Options["your-scope-option"] = child.ID

    childAsset := &inventory.Asset{
        Name:        child.Name,
        Platform:    child.Platform,
        Connections: []*inventory.Config{childConfig},
    }

    // Only give platform IDs to assets that should be scanned.
    // Without platform IDs, the scanner skips them but AssetExplorer
    // still connects to trigger the next discovery stage.
    if isScopeTargeted {
        childAsset.PlatformIds = []string{child.PlatformId}
    }

    in.Spec.Assets = append(in.Spec.Assets, childAsset)
}
```

**Key rules:**
- `DiscoveryAuto` and `DiscoveryAll` targets mean everything is scannable — always keep platform IDs
- Mixed targets (e.g., `--discover pods,namespaces`) — if the intermediate level IS a target, keep its platform IDs
- Leaf assets at the bottom of the hierarchy always keep their platform IDs if they match targets

### Step 6: Gate resource methods at higher scopes (if needed)

When the root scope is scanned, resource methods that load lower-scope data should return empty results to avoid loading everything into the root's cache. This is optional but important for large providers.

```go
func isRootScopedConnection(r *plugin.Runtime) bool {
    conn := r.Connection.(YourConnection)
    cfg := conn.InventoryConfig()
    if _, ok := cfg.Options[plugin.OptionStagedDiscovery]; !ok {
        return false // Legacy path — don't gate anything
    }
    return cfg.Options["your-scope-option"] == "" // Root scope = no child scope set
}

// In a resource method that should only run at child scope:
func (r *mqlYourProvider) childScopedResources() ([]interface{}, error) {
    if isRootScopedConnection(r.MqlRuntime) {
        return []interface{}{}, nil // Empty at root scope — will be loaded per child
    }
    // ... normal implementation
}
```

### Step 7: Verify both paths and discovery targets

Both the legacy and staged paths must discover the same final set of assets (same platform IDs, same names). They differ only in how discovery is chunked. Also verify that discovery targets correctly filter scannable assets.

```bash
# Build and install
make providers/build/<name> && make providers/install/<name>

# Test legacy path (no staged discovery flag — simulates old client)
# This should work exactly as before
mql shell <provider-args>

# Test staged path (AssetExplorer sets the flag automatically)
# Verify the same assets appear
mql shell <provider-args>

# Test discovery target filtering (e.g., only pods, only instances)
# Verify that intermediate assets are traversed but not scanned
mql shell <provider-args> --discover <specific-target>

# Run existing tests
go test ./providers/<name>/...
```

### Step 8: Update .lr.versions if new resources were added

If you added any new resources or fields to support staged discovery, update the `.lr.versions` file:

```bash
make providers/mqlr
./mqlr generate providers/<name>/resources/<name>.lr --dist providers/<name>/resources
```

## Checklist

- [ ] `Discover()` routes to staged vs legacy based on `OptionStagedDiscovery`
- [ ] Legacy path is preserved unchanged with `TODO(v15)` comment
- [ ] Stage 1 returns child scope assets WITHOUT `WithParentConnectionId` (cache isolation)
- [ ] Stage 2+ returns leaf assets WITH `WithParentConnectionId` (cache sharing within scope)
- [ ] Child connection configs include the scope option that triggers the next stage
- [ ] `OptionStagedDiscovery` is propagated via `Clone()` to all child configs
- [ ] Resource methods at root scope are gated to avoid loading child-scope data into root cache
- [ ] Intermediate assets have platform IDs stripped when not in discovery targets
- [ ] `DiscoveryAuto` / `DiscoveryAll` targets always keep platform IDs on all assets
- [ ] Both legacy and staged paths produce the same set of assets
- [ ] Discovery target filtering works (e.g., `--discover pods` only scans pods, not namespaces)
- [ ] `go build ./providers/<name>/...` compiles
- [ ] `go test ./providers/<name>/...` passes
- [ ] `make test/lint` passes
