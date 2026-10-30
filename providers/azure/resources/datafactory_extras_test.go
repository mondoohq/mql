// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory/v11"
	"github.com/stretchr/testify/assert"
)

func TestFactoryResourceGroup(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		wantRG      string
		wantFactory string
		wantErr     bool
	}{
		{
			name:        "well-formed factory id",
			id:          "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.DataFactory/factories/myadf",
			wantRG:      "my-rg",
			wantFactory: "myadf",
		},
		{
			name:    "missing factories segment",
			id:      "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.DataFactory",
			wantErr: true,
		},
		{
			name:    "malformed id",
			id:      "not-an-arm-id",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rg, factory, err := factoryResourceGroup(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantRG, rg)
			assert.Equal(t, tc.wantFactory, factory)
		})
	}
}

func TestSortedParameterNames(t *testing.T) {
	t.Run("nil map returns empty", func(t *testing.T) {
		assert.Empty(t, sortedParameterNames(nil))
	})
	t.Run("entries returned alphabetically", func(t *testing.T) {
		params := map[string]*armdatafactory.ParameterSpecification{
			"zeta":  {},
			"alpha": {},
			"mu":    {},
		}
		got := sortedParameterNames(params)
		assert.Equal(t, []any{"alpha", "mu", "zeta"}, got)
	})
}

func TestDictReferencesAzureKeyVaultSecret(t *testing.T) {
	t.Run("flat object without KV reference", func(t *testing.T) {
		input := map[string]any{
			"connectionString": "Server=tcp:foo.database.windows.net;Password=plain",
			"type":             "AzureSqlDatabase",
		}
		assert.False(t, dictReferencesAzureKeyVaultSecret(input))
	})

	t.Run("KV reference at top level", func(t *testing.T) {
		input := map[string]any{
			"type":       "AzureKeyVaultSecret",
			"secretName": "sql-password",
		}
		assert.True(t, dictReferencesAzureKeyVaultSecret(input))
	})

	t.Run("KV reference nested under typeProperties", func(t *testing.T) {
		input := map[string]any{
			"type": "AzureSqlDatabase",
			"typeProperties": map[string]any{
				"password": map[string]any{
					"type":       "AzureKeyVaultSecret",
					"secretName": "sql-password",
					"store": map[string]any{
						"referenceName": "kv1",
					},
				},
			},
		}
		assert.True(t, dictReferencesAzureKeyVaultSecret(input))
	})

	t.Run("KV reference inside array", func(t *testing.T) {
		input := map[string]any{
			"connectionStrings": []any{
				map[string]any{
					"type":       "AzureKeyVaultSecret",
					"secretName": "x",
				},
			},
		}
		assert.True(t, dictReferencesAzureKeyVaultSecret(input))
	})

	t.Run("type field with non-KV value does not match", func(t *testing.T) {
		input := map[string]any{
			"type": "SecureString",
			"value": map[string]any{
				"type":  "Expression",
				"value": "@pipeline().parameters.foo",
			},
		}
		assert.False(t, dictReferencesAzureKeyVaultSecret(input))
	})

	t.Run("non-map non-array input never matches", func(t *testing.T) {
		assert.False(t, dictReferencesAzureKeyVaultSecret("AzureKeyVaultSecret"))
		assert.False(t, dictReferencesAzureKeyVaultSecret(42))
		assert.False(t, dictReferencesAzureKeyVaultSecret(nil))
	})
}
