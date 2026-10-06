// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

func TestAssetRoot(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		want     string
	}{
		{"no platform", nil, "azuredevops"},
		{"organization", connection.NewOrgPlatform("mondoo-ado-scan-test"), "azuredevops.organization"},
		{"repository", connection.NewRepoPlatform("mondoo-ado-scan-test", "scan-test"), "azuredevops.repository"},
		{"a platform this provider does not assign", &inventory.Platform{Name: "other"}, "azuredevops"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, assetRoot(tc.platform))
		})
	}
}

// Every platform the provider assigns has a root of its own, so a new platform
// cannot be added without deciding what it roots at.
func TestEveryPlatformHasARoot(t *testing.T) {
	for _, p := range connection.Platforms {
		assert.NotEqual(t, "azuredevops", assetRoot(&inventory.Platform{Name: p.Name}), p.Name)
	}
}
