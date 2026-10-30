// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAzureProviderOperations(t *testing.T) {
	c := azureCatalog(t)
	assert.True(t, c.hasExact("Microsoft.Kusto/register/action"), "provider-level operation")
	assert.True(t, c.hasExact("Microsoft.Kusto/Clusters/Databases/read"), "resource-type operation")
	assert.True(t, c.hasExact("Microsoft.Web/sites/Read"), "null resourceTypes is fine")
	canon, ok := c.canonical("microsoft.web/sites/read")
	assert.True(t, ok)
	assert.Equal(t, "Microsoft.Web/sites/Read", canon)

	// The API wraps the list in "value"; the same parser reads both forms.
	wrapped := newCatalog()
	require.NoError(t, parseAzureProviderOperations([]byte(`{"value":[{"name":"Microsoft.X","operations":[{"name":"Microsoft.X/things/read"}]}]}`), wrapped))
	assert.True(t, wrapped.hasExact("Microsoft.X/things/read"))
	err := parseAzureProviderOperations([]byte(`{"value":[]}`), newCatalog())
	assert.EqualError(t, err, "providerOperations: the registry answered with no providers", "an empty registry is a fetch problem")
	assert.Error(t, parseAzureProviderOperations([]byte(`{"value":"nope"}`), newCatalog()), "a malformed answer is reported as such")
}

func TestCheckManifestAzureIgnoresCase(t *testing.T) {
	m := manifest{Provider: "azure", Permissions: []string{
		"microsoft.kusto/clusters/databases/read", // case differs: fine for Azure
		"Microsoft.Kusto/databases/read",          // not registered: a custom role naming it is refused
		"Microsoft.Signalr/signalr/read",          // unknown namespace
	}}
	r := checkManifest(m, azureCatalog(t))
	assert.Equal(t, 1, r.Valid)
	assert.Empty(t, r.Notes, "a spelling that differs from the registry's is not worth a note on Azure")
	require.Len(t, r.Problems, 2)
	assert.Equal(t, "Microsoft.Kusto/databases/read", r.Problems[0].Permission)
	assert.Equal(t, "not a known registered operation", r.Problems[0].Message)
	assert.Equal(t, "Microsoft.Signalr/signalr/read", r.Problems[1].Permission)
	assert.Contains(t, r.Problems[1].Message, `resource provider namespace "Microsoft.Signalr"`)
	assert.False(t, r.ok())
}
