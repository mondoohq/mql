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
	for _, p := range Platforms {
		require.NotEmpty(t, p.Name)
		assert.Same(t, p, PlatformByName(p.Name))
	}
}

func TestPlatformBuildersConsistent(t *testing.T) {
	builders := map[string]func() *inventory.Platform{
		"nmap-host":   nmapHostPlatform,
		"nmap-domain": nmapDomainPlatform,
		"nmap-org":    nmapPlatform,
	}

	for name, build := range builders {
		entry := PlatformByName(name)
		require.NotNil(t, entry, name)
		pf := build()
		assert.True(t, entry.Consistent(pf), name)
		assert.Equal(t, entry.Title, pf.Title, name)
	}
}
