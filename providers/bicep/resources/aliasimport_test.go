// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
)

// F6: `import { sku as skuAlias } from './shared.bicep'` stores the symbol
// verbatim as "sku as skuAlias", so filtering the target file's declarations
// by exact name never matches and the import resolves to nothing.
func TestImportAliasedSymbolsResolve(t *testing.T) {
	dir := filepath.Join("testdata", "aliasimport")
	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "bicep", Options: map[string]string{"path": dir}},
		},
	}
	conn, err := connection.NewBicepConnection(0, asset, asset.Connections[0])
	require.NoError(t, err)
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &mapResources{m: map[string]plugin.Resource{}},
	}

	var imp *mqlBicepImport
	for _, f := range conn.BicepFiles() {
		if filepath.Base(f.Path) != "main.bicep" {
			continue
		}
		mqlF, err := newMqlBicepFile(runtime, f)
		require.NoError(t, err)
		imps, err := mqlF.imports()
		require.NoError(t, err)
		require.Len(t, imps, 1)
		imp = imps[0].(*mqlBicepImport)
	}
	require.NotNil(t, imp, "main.bicep not found")

	target, err := imp.targetFile()
	require.NoError(t, err)
	require.NotNil(t, target, "the aliased import's target file resolves fine")

	types, err := imp.resolvedTypes()
	require.NoError(t, err)
	require.Len(t, types, 1, "an aliased type import must resolve to the underlying type")
	assert.Equal(t, "sku", types[0].(*mqlBicepType).Name.Data)

	funcs, err := imp.resolvedFunctions()
	require.NoError(t, err)
	require.Len(t, funcs, 1, "an aliased function import must resolve to the underlying function")
	assert.Equal(t, "buildName", funcs[0].(*mqlBicepFunction).Name.Data)
}
