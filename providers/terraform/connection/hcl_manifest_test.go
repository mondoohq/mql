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

// TestDotTerraformSubdir pins which directories under a vendored .terraform
// cache the walk descends into. Only the module manifest is read from there, so
// everything except .terraform itself and .terraform/modules can be skipped
// whole — notably .terraform/providers, which holds the vendored provider
// binaries and is routinely hundreds of megabytes.
func TestDotTerraformSubdir(t *testing.T) {
	tests := []struct {
		name        string
		rel         string
		wantSub     string
		wantUnder   bool
		wantDescend bool
	}{
		{name: "outside the cache", rel: "modules/vpc", wantSub: "", wantUnder: false, wantDescend: false},
		{name: "the cache itself", rel: ".terraform", wantSub: "", wantUnder: true, wantDescend: true},
		{name: "the modules dir", rel: ".terraform/modules", wantSub: "modules", wantUnder: true, wantDescend: true},
		{name: "a vendored module", rel: ".terraform/modules/vpc", wantSub: "modules/vpc", wantUnder: true, wantDescend: false},
		{name: "the provider cache", rel: ".terraform/providers", wantSub: "providers", wantUnder: true, wantDescend: false},
		{
			name:    "deep inside the provider cache",
			rel:     ".terraform/providers/registry.terraform.io/hashicorp/aws/5.0.0/linux_amd64",
			wantSub: "providers/registry.terraform.io/hashicorp/aws/5.0.0/linux_amd64", wantUnder: true, wantDescend: false,
		},
		// A monorepo has one cache per stack, so the match must be on the path
		// segment rather than on depth.
		{name: "nested cache in a monorepo", rel: "stacks/prod/.terraform", wantSub: "", wantUnder: true, wantDescend: true},
		{name: "nested cache modules dir", rel: "stacks/prod/.terraform/modules", wantSub: "modules", wantUnder: true, wantDescend: true},
		{name: "nested cache providers", rel: "stacks/prod/.terraform/providers", wantSub: "providers", wantUnder: true, wantDescend: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, under := dotTerraformSubdir(tt.rel)
			assert.Equal(t, tt.wantUnder, under, "under .terraform")
			assert.Equal(t, tt.wantSub, sub, "subdir")

			// This mirrors the walk's descend decision.
			descend := under && (sub == "" || sub == modulesDir)
			assert.Equal(t, tt.wantDescend, descend, "descend")
		})
	}
}
