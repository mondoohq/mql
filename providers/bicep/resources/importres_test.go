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

// importResRuntime builds a runtime backed by a real BicepConnection scanning
// the importres fixture directory, plus an in-memory resource cache so
// CreateResource/NewResource dedupe by __id.
func importResRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	dir := filepath.Join("testdata", "importres")
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

// mainImports returns all materialized imports of importres/main.bicep.
func mainImports(t *testing.T, runtime *plugin.Runtime) []*mqlBicepImport {
	t.Helper()
	conn := runtime.Connection.(*connection.BicepConnection)
	for _, f := range conn.BicepFiles() {
		if filepath.Base(f.Path) != "main.bicep" {
			continue
		}
		mqlF, err := newMqlBicepFile(runtime, f)
		require.NoError(t, err)
		imps, err := mqlF.imports()
		require.NoError(t, err)
		out := make([]*mqlBicepImport, 0, len(imps))
		for _, imp := range imps {
			out = append(out, imp.(*mqlBicepImport))
		}
		return out
	}
	t.Fatal("main.bicep not found")
	return nil
}

// findImport returns the first import matching the predicate.
func findImport(t *testing.T, imps []*mqlBicepImport, match func(*mqlBicepImport) bool) *mqlBicepImport {
	t.Helper()
	for _, imp := range imps {
		if match(imp) {
			return imp
		}
	}
	t.Fatal("no matching import found")
	return nil
}

func typeNames(t *testing.T, list []any) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, e := range list {
		names[e.(*mqlBicepType).Name.Data] = true
	}
	return names
}

func funcNames(t *testing.T, list []any) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, e := range list {
		names[e.(*mqlBicepFunction).Name.Data] = true
	}
	return names
}

func TestImportNamedResolvesTypeAndFunction(t *testing.T) {
	runtime := importResRuntime(t)
	imps := mainImports(t, runtime)

	// The named import is `import { sku, buildName } from './shared.bicep'`.
	named := findImport(t, imps, func(i *mqlBicepImport) bool {
		return i.Source.Data == "./shared.bicep" && !i.Wildcard.Data
	})

	target, err := named.targetFile()
	require.NoError(t, err)
	require.NotNil(t, target, "named import should resolve to its target file")
	assert.Equal(t, "shared.bicep", filepath.Base(target.Path.Data))

	// Only the named type is brought in (sku), not tier.
	types, err := named.resolvedTypes()
	require.NoError(t, err)
	names := typeNames(t, types)
	assert.True(t, names["sku"], "named type sku should be resolved")
	assert.False(t, names["tier"], "unnamed type tier must not be resolved")
	assert.Len(t, types, 1)

	// Only the named function is brought in (buildName).
	funcs, err := named.resolvedFunctions()
	require.NoError(t, err)
	fnames := funcNames(t, funcs)
	assert.True(t, fnames["buildName"], "named func buildName should be resolved")
	assert.Len(t, funcs, 1)
}

func TestImportWildcardResolvesAll(t *testing.T) {
	runtime := importResRuntime(t)
	imps := mainImports(t, runtime)

	// The wildcard import is `import * as shared from './shared.bicep'`.
	wild := findImport(t, imps, func(i *mqlBicepImport) bool {
		return i.Wildcard.Data
	})
	assert.Equal(t, "shared", wild.Namespace.Data)

	target, err := wild.targetFile()
	require.NoError(t, err)
	require.NotNil(t, target, "wildcard import should resolve to its target file")
	assert.Equal(t, "shared.bicep", filepath.Base(target.Path.Data))

	// A wildcard import brings in ALL exported types and functions.
	types, err := wild.resolvedTypes()
	require.NoError(t, err)
	names := typeNames(t, types)
	assert.True(t, names["sku"])
	assert.True(t, names["tier"])
	assert.Len(t, types, 2)

	funcs, err := wild.resolvedFunctions()
	require.NoError(t, err)
	fnames := funcNames(t, funcs)
	assert.True(t, fnames["buildName"])
	assert.Len(t, funcs, 1)
}

func TestImportProviderTargetIsNull(t *testing.T) {
	runtime := importResRuntime(t)
	imps := mainImports(t, runtime)

	// The provider import is `import 'az@2.0.0'`.
	prov := findImport(t, imps, func(i *mqlBicepImport) bool {
		return i.Source.Data == "az@2.0.0"
	})

	target, err := prov.targetFile()
	require.NoError(t, err)
	assert.Nil(t, target, "provider import target must be null")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, prov.TargetFile.State&(plugin.StateIsSet|plugin.StateIsNull))

	types, err := prov.resolvedTypes()
	require.NoError(t, err)
	assert.Empty(t, types)

	funcs, err := prov.resolvedFunctions()
	require.NoError(t, err)
	assert.Empty(t, funcs)
}

// TestImportTargetOutsideRootIsNull guards against path traversal: an import
// whose source resolves to a real, readable .bicep OUTSIDE the scanned root
// must still resolve to null. targetFile() only returns files the scan
// discovered and never reads an arbitrary path, so a crafted reference can't
// disclose out-of-root file contents via bicep.file.content.
func TestImportTargetOutsideRootIsNull(t *testing.T) {
	runtime := importResRuntime(t)

	// Precondition: the traversal target genuinely exists and is readable, so a
	// null result proves the read was refused by policy — not just absent.
	outside := filepath.Join("testdata", "loops.bicep")
	_, err := os.Stat(outside)
	require.NoError(t, err, "fixture precondition: %s must exist", outside)

	imps := mainImports(t, runtime)
	escape := findImport(t, imps, func(i *mqlBicepImport) bool {
		return i.Source.Data == "../loops.bicep"
	})

	target, err := escape.targetFile()
	require.NoError(t, err)
	assert.Nil(t, target, "out-of-root import target must be null (no arbitrary file read)")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, escape.TargetFile.State&(plugin.StateIsSet|plugin.StateIsNull))

	types, err := escape.resolvedTypes()
	require.NoError(t, err)
	assert.Empty(t, types)

	funcs, err := escape.resolvedFunctions()
	require.NoError(t, err)
	assert.Empty(t, funcs)
}
