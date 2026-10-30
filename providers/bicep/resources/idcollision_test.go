// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F10: two declarations sharing a symbolic name in one file produced the same
// `__id`, so the cache handed the second list entry the FIRST declaration's
// data. The input is invalid Bicep, but the id must still be collision-proof.
func TestDuplicateSymbolicNamesGetDistinctIDs(t *testing.T) {
	src := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'first'
  location: 'eastus'
}

resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'second'
  location: 'westus'
}
`
	parsed := parseBicep(src)
	require.Len(t, parsed.resources, 2)

	runtime := testRuntime()
	resolver := newSymbolResolver("dup.bicep", parsed)
	list, err := createMqlResources(runtime, "dup.bicep", parsed.resources, resolver)
	require.NoError(t, err)
	require.Len(t, list, 2)

	first := list[0].(*mqlBicepResource)
	second := list[1].(*mqlBicepResource)

	assert.NotEqual(t, first.__id, second.__id, "duplicate symbolic names must not share a cache id")
	assert.Equal(t, "first", first.Name.Data)
	assert.Equal(t, "second", second.Name.Data,
		"the second declaration must report its own data, not the first's")
}
