// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventoryvalidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// testProviders mirrors the relevant shape of real provider metadata: a k8s
// provider whose connector declares "namespaces"/"context", and an azure
// provider with "subscriptions". The schema is derived from these without
// touching any installed provider.
func testProviders() []*plugin.Provider {
	return []*plugin.Provider{
		{
			Name:            "k8s",
			ConnectionTypes: []string{"k8s"},
			Connectors: []plugin.Connector{
				{
					Name:    "k8s",
					Aliases: []string{"kubernetes"},
					Flags: []plugin.Flag{
						{Long: "namespaces", Type: plugin.FlagType_String},
						{Long: "context", Type: plugin.FlagType_String},
					},
				},
			},
		},
		{
			Name:            "azure",
			ConnectionTypes: []string{"azure"},
			Connectors: []plugin.Connector{
				{
					Name: "azure",
					Flags: []plugin.Flag{
						{Long: "subscriptions", Type: plugin.FlagType_String},
					},
				},
			},
		},
	}
}

func inv(conns ...*inventory.Config) *inventory.Inventory {
	return &inventory.Inventory{
		Spec: &inventory.InventorySpec{
			Assets: []*inventory.Asset{{Id: "test-asset", Connections: conns}},
		},
	}
}

func TestBuildSchema_resolvesTypesAndAliases(t *testing.T) {
	s := BuildSchema(testProviders())

	// Connection types are reachable by ConnectionTypes, connector name, and alias.
	_, k8s := s.optionKeys["k8s"]
	_, kubernetes := s.optionKeys["kubernetes"]
	_, azure := s.optionKeys["azure"]
	assert.True(t, k8s, "k8s type resolves")
	assert.True(t, kubernetes, "k8s alias resolves")
	assert.True(t, azure, "azure type resolves")

	_, unknown := s.optionKeys["aws"]
	assert.False(t, unknown, "uninstalled type does not resolve")
}

func TestCheck_validOptions(t *testing.T) {
	s := BuildSchema(testProviders())
	findings := Check(inv(&inventory.Config{
		Type:    "k8s",
		Options: map[string]string{"namespaces": "default", "context": "prod"},
	}), s, false)
	assert.Empty(t, findings, "known options produce no findings")
}

func TestCheck_unknownOption(t *testing.T) {
	s := BuildSchema(testProviders())
	findings := Check(inv(&inventory.Config{
		Type: "k8s",
		// "namespace" (singular) is a typo for "namespaces"; "subscriptions"
		// belongs to a different provider.
		Options: map[string]string{"namespace": "default", "subscriptions": "x"},
	}), s, false)

	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, SeverityWarning, f.Severity)
		assert.Equal(t, "k8s", f.Type)
		assert.Equal(t, "test-asset", f.Asset)
	}
	// Deterministic order: keys are sorted, so "namespace" precedes "subscriptions".
	assert.Contains(t, findings[0].Message, `"namespace"`)
	assert.Contains(t, findings[1].Message, `"subscriptions"`)
}

func TestCheck_strictPromotesToError(t *testing.T) {
	s := BuildSchema(testProviders())
	findings := Check(inv(&inventory.Config{
		Type:    "k8s",
		Options: map[string]string{"bogus": "1"},
	}), s, true)
	require.Len(t, findings, 1)
	assert.Equal(t, SeverityError, findings[0].Severity)
}

func TestCheck_unknownConnectionType(t *testing.T) {
	s := BuildSchema(testProviders())
	findings := Check(inv(&inventory.Config{
		Type:    "made-up",
		Options: map[string]string{"anything": "1"},
	}), s, false)

	// Only the type finding — options are not validated for an unknown type.
	require.Len(t, findings, 1)
	assert.Equal(t, "made-up", findings[0].Type)
	assert.Contains(t, findings[0].Message, "not provided by any installed provider")
}

func TestCheck_nilSafe(t *testing.T) {
	s := BuildSchema(testProviders())
	assert.Empty(t, Check(nil, s, false))
	assert.Empty(t, Check(&inventory.Inventory{}, s, false))
	assert.Empty(t, Check(inv(), nil, false))
}

func TestCheck_assetLabelFallback(t *testing.T) {
	s := BuildSchema(testProviders())
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{
			{Name: "named", Connections: []*inventory.Config{{Type: "made-up"}}},
			{Connections: []*inventory.Config{{Type: "made-up"}}},
		},
	}}
	findings := Check(in, s, false)
	require.Len(t, findings, 2)
	assert.Equal(t, "named", findings[0].Asset)
	assert.Equal(t, "#1", findings[1].Asset)
}
