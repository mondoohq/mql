// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestPlatformCatalog(t *testing.T) {
	require.NotEmpty(t, Platforms)
	for _, pi := range Platforms {
		require.NotEmpty(t, pi.Name)
		assert.Same(t, pi, PlatformByName(pi.Name), pi.Name)

		p := &inventory.Platform{}
		pi.Apply(p)
		assert.True(t, pi.Consistent(p), pi.Name)
		assert.Equal(t, pi.Title, p.Title, pi.Name)
	}
}

// Every detectable vendor (and the generic fallback) must be present in the
// static catalog, so the platform stamped on an asset is always declared.
func TestCatalogCoversVendors(t *testing.T) {
	for _, v := range vendors {
		assert.NotNil(t, PlatformByName(v.Platform), v.Platform)
	}
	assert.NotNil(t, PlatformByName(genericVendor.Platform), genericVendor.Platform)
}
