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
		t.Run(pi.Name, func(t *testing.T) {
			require.NotNil(t, PlatformByName(pi.Name))

			p := &inventory.Platform{}
			pi.Apply(p)
			assert.True(t, pi.Consistent(p), "applied platform should be consistent with catalog entry")
			assert.Equal(t, pi.Title, p.Title)
			assert.Equal(t, pi.Name, p.Name)
		})
	}
}
