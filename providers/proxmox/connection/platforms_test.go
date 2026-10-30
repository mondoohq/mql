// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestPlatformCatalog(t *testing.T) {
	require.NotEmpty(t, Platforms)

	pi, ok := PlatformByName("proxmox")
	require.True(t, ok)

	p := &inventory.Platform{}
	pi.Apply(p)

	require.True(t, pi.Consistent(p))
	require.Equal(t, "Proxmox VE", p.Title)
	require.Equal(t, pi.Title, p.Title)
}
