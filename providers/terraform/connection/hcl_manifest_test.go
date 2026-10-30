// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestTerraform(t *testing.T) {
	p, err := NewHclConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					"path": "./testdata/hcl",
				},
				Type: "hcl",
			},
		},
	})
	require.NoError(t, err)

	files := p.Parser().Files()
	assert.Equal(t, len(files), 2)
}

func TestModuleManifestIssue676(t *testing.T) {
	// See https://github.com/mondoohq/mql/issues/676
	t.Run("issue#676", func(t *testing.T) {
		p, err := NewHclConnection(0, &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Options: map[string]string{
						"path": "./testdata/issue676",
					},
					Type: "hcl",
				},
			},
		})
		require.NoError(t, err)

		moduleManifest := p.ModulesManifest()
		require.NotNil(t, moduleManifest)
		require.Len(t, moduleManifest.Records, 3)
	})

	// https://github.com/mondoohq/cnspec/issues/605
	t.Run("issue#676", func(t *testing.T) {
		p, err := NewHclConnection(0, &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Options: map[string]string{
						"path":                 "./testdata/issue676",
						"ignore-dot-terraform": "true",
					},
					Type: "hcl",
				},
			},
		})
		require.NoError(t, err)

		moduleManifest := p.ModulesManifest()
		require.Nil(t, moduleManifest)
	})
}
