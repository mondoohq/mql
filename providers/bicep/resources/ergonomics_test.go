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

func TestParseBicepValueTyped(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want any
	}{
		{"bool true", "true", true},
		{"bool false", "false", false},
		{"integer", "90", float64(90)},
		{"negative integer", "-5", float64(-5)},
		{"float", "1.5", 1.5},
		{"zero", "0", float64(0)},
		{"empty", "", ""},
		{"single-quoted string", "'Standard_LRS'", "Standard_LRS"},
		{"quoted number stays a string", "'22'", "22"},
		{"quoted bool stays a string", "'true'", "true"},
		{"expression stays raw", "resourceGroup().location", "resourceGroup().location"},
		{"bare identifier stays raw", "myParam", "myParam"},
		{"object value", "{ enabled: true }", map[string]any{"enabled": true}},
		{"array of numbers", "[1, 2, 3]", []any{float64(1), float64(2), float64(3)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, parseBicepValue(c.in))
		})
	}
}

func TestParseBicepNumber(t *testing.T) {
	cases := []struct {
		in   string
		want float64
		ok   bool
	}{
		{"90", 90, true},
		{"-5", -5, true},
		{"1.5", 1.5, true},
		{"0", 0, true},
		{"", 0, false},
		{"90abc", 0, false},
		{"resourceGroup()", 0, false},
		{"1.2.3", 0, false},
		{"TLS1_2", 0, false},
		// special float forms strconv.ParseFloat would otherwise accept
		{"Inf", 0, false},
		{"+Inf", 0, false},
		{"-Inf", 0, false},
		{"NaN", 0, false},
	}
	for _, c := range cases {
		got, ok := parseBicepNumber(c.in)
		assert.Equal(t, c.ok, ok, c.in)
		if c.ok {
			assert.Equal(t, c.want, got, c.in)
		}
	}
}

func TestStripLiteralQuotes(t *testing.T) {
	assert.Equal(t, "VirtualMachines", stripLiteralQuotes("'VirtualMachines'"))
	assert.Equal(t, "default", stripLiteralQuotes("'default'"))
	assert.Equal(t, "", stripLiteralQuotes("''"))
	// interpolated literal: the outer quotes are stripped, content kept
	assert.Equal(t, "${env}-sa", stripLiteralQuotes("'${env}-sa'"))
	// unquoted expressions and identifiers are left untouched
	assert.Equal(t, "resourceGroup().name", stripLiteralQuotes("resourceGroup().name"))
	assert.Equal(t, "storageName", stripLiteralQuotes("storageName"))
	assert.Equal(t, "", stripLiteralQuotes(""))
	assert.Equal(t, "'", stripLiteralQuotes("'")) // too short to be a quoted pair
}

func TestResourceNameQuoteStripping(t *testing.T) {
	src := `resource pricing 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
}
resource sa 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
}`
	parsed := parseBicep(src)
	resolver := newSymbolResolver("inline.bicep", parsed)
	runtime := testRuntime()

	pricing, err := newMqlBicepResource(runtime, "bicep.resource:inline:pricing", findResource(parsed, "pricing"), resolver, nil)
	require.NoError(t, err)
	// a literal name has its surrounding quotes stripped, so `name == "VirtualMachines"` matches
	assert.Equal(t, "VirtualMachines", pricing.Name.Data)
	// nameTree still classifies it as a literal — it reads the raw, quoted form
	nt, err := pricing.nameTree()
	require.NoError(t, err)
	assert.Equal(t, exprKindLiteral, nt.node.kind)

	sa, err := newMqlBicepResource(runtime, "bicep.resource:inline:sa", findResource(parsed, "sa"), resolver, nil)
	require.NoError(t, err)
	// an expression-valued name is left untouched
	assert.Equal(t, "storageName", sa.Name.Data)
}

func TestBicepResourcesFlatten(t *testing.T) {
	dir := filepath.Join("testdata", "flatten")
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
	b := &mqlBicep{MqlRuntime: runtime}

	list, err := b.resources()
	require.NoError(t, err)

	types := map[string]bool{}
	for _, r := range list {
		types[r.(*mqlBicepResource).Type.Data] = true
	}
	// resources from both files appear in the single flattened list
	assert.True(t, types["Microsoft.Storage/storageAccounts"], "expected the resource from a.bicep")
	assert.True(t, types["Microsoft.Network/networkSecurityGroups"], "expected the resource from b.bicep")
	assert.Len(t, list, 2)
}
