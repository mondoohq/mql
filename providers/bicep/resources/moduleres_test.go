// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
)

// moduleResRuntime builds a runtime backed by a real BicepConnection scanning
// the moduleres fixture directory, plus an in-memory resource cache so
// CreateResource/NewResource dedupe by __id.
func moduleResRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	dir := filepath.Join("testdata", "moduleres")
	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "bicep", Options: map[string]string{"path": dir}},
		},
	}
	conn, err := connection.NewBicepConnection(0, asset, asset.Connections[0])
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &mapResources{m: map[string]plugin.Resource{}},
	}
}

// findModule returns the materialized bicep.module with the given symbolic name
// from the file whose base name matches.
func findModule(t *testing.T, runtime *plugin.Runtime, fileBase, moduleName string) *mqlBicepModule {
	t.Helper()
	conn := runtime.Connection.(*connection.BicepConnection)
	for _, f := range conn.BicepFiles() {
		if filepath.Base(f.Path) != fileBase {
			continue
		}
		mqlF, err := newMqlBicepFile(runtime, f)
		require.NoError(t, err)
		mods, err := mqlF.modules()
		require.NoError(t, err)
		for _, m := range mods {
			mod := m.(*mqlBicepModule)
			if mod.Name.Data == moduleName {
				return mod
			}
		}
	}
	t.Fatalf("module %q not found in %q", moduleName, fileBase)
	return nil
}

func TestModuleTargetResolvesLocalFile(t *testing.T) {
	runtime := moduleResRuntime(t)

	mod := findModule(t, runtime, "main.bicep", "network")
	require.False(t, mod.IsRegistry.Data)

	target, err := mod.target()
	require.NoError(t, err)
	require.NotNil(t, target, "local module should resolve to its target file")

	// The resolved file is the discovered modules/child.bicep.
	assert.Equal(t, "child.bicep", filepath.Base(target.Path.Data))

	// It must be the SAME cached instance as the connection's loaded child file.
	conn := runtime.Connection.(*connection.BicepConnection)
	var childPath string
	for _, f := range conn.BicepFiles() {
		if filepath.Base(f.Path) == "child.bicep" {
			childPath = f.Path
		}
	}
	require.NotEmpty(t, childPath)
	assert.Equal(t, filepath.Clean(childPath), filepath.Clean(target.Path.Data))

	// The child file's resources and parameters are reachable through the target.
	resources, err := target.resources()
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, "Microsoft.Network/virtualNetworks", resources[0].(*mqlBicepResource).Type.Data)

	params, err := target.parameters()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, p := range params {
		names[p.(*mqlBicepParameter).Name.Data] = true
	}
	assert.True(t, names["location"])
	assert.True(t, names["vnetName"])
}

func TestModuleTargetReturnsSameCachedFile(t *testing.T) {
	runtime := moduleResRuntime(t)

	mod := findModule(t, runtime, "main.bicep", "network")
	first, err := mod.target()
	require.NoError(t, err)
	require.NotNil(t, first)

	// Materializing the child file directly yields the same cached pointer the
	// target() accessor returns (same __id).
	conn := runtime.Connection.(*connection.BicepConnection)
	for _, f := range conn.BicepFiles() {
		if filepath.Base(f.Path) == "child.bicep" {
			direct, err := newMqlBicepFile(runtime, f)
			require.NoError(t, err)
			assert.Same(t, direct, first)
		}
	}
}

func TestModuleTargetRegistryIsNull(t *testing.T) {
	runtime := moduleResRuntime(t)

	mod := findModule(t, runtime, "main.bicep", "shared")
	require.True(t, mod.IsRegistry.Data, "br: source should be flagged as registry")

	target, err := mod.target()
	require.NoError(t, err)
	assert.Nil(t, target, "registry module target must be null")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, mod.Target.State&(plugin.StateIsSet|plugin.StateIsNull))
}

// TestModuleTargetOutsideRootIsNull guards against path traversal: a module
// whose source resolves to a real, readable .bicep OUTSIDE the scanned root
// must still resolve to null. target() only returns files the scan discovered
// and never reads an arbitrary path, so a crafted reference can't disclose
// out-of-root file contents via bicep.file.content.
func TestModuleTargetOutsideRootIsNull(t *testing.T) {
	runtime := moduleResRuntime(t)

	// Precondition: the traversal target genuinely exists and is readable, so a
	// null result proves the read was refused by policy — not just absent.
	outside := filepath.Join("testdata", "loops.bicep")
	_, err := os.Stat(outside)
	require.NoError(t, err, "fixture precondition: %s must exist", outside)

	mod := findModule(t, runtime, "main.bicep", "escape")
	require.False(t, mod.IsRegistry.Data, "../loops.bicep is a local reference, not a registry one")

	target, err := mod.target()
	require.NoError(t, err)
	assert.Nil(t, target, "out-of-root module target must be null (no arbitrary file read)")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, mod.Target.State&(plugin.StateIsSet|plugin.StateIsNull))
}
