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

// The runtime platform builders must emit platforms the catalog declares.
func TestRuntimePlatformsConsistent(t *testing.T) {
	assert.True(t, PlatformByName("portainer-server").Consistent(InstancePlatform()))

	env := EnvironmentPlatform(5) // kubernetes
	assert.True(t, PlatformByName("portainer-environment").Consistent(env))
	// The dynamic title survives Apply.
	assert.Equal(t, "Portainer Environment (kubernetes)", env.Title)
}
