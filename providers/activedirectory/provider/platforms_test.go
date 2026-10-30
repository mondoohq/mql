// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

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
		got, ok := PlatformByName(pi.Name)
		require.True(t, ok, pi.Name)
		assert.Same(t, pi, got, pi.Name)

		p := &inventory.Platform{}
		pi.Apply(p)
		assert.True(t, pi.Consistent(p), pi.Name)
		assert.Equal(t, pi.Title, p.Title, pi.Name)
	}
}
