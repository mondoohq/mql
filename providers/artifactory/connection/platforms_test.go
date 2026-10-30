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

// The platform the provider stamps on an asset must come from the catalog, so
// a rename in one place cannot leave the other behind.
func TestInstancePlatformIsDeclared(t *testing.T) {
	p := NewArtifactoryPlatform("jfrt@01ab2c3d", "7.90.10")

	require.NotNil(t, PlatformByName(p.Name))
	assert.Equal(t, "artifactory", p.Name)
	assert.Equal(t, "api", p.Kind)
	assert.Equal(t, "artifactory", p.Runtime)
	assert.Equal(t, "7.90.10", p.Version)
	assert.Equal(t, []string{"saas", "artifactory", "jfrt@01ab2c3d"}, p.TechnologyUrlSegments)
	assert.True(t, PlatformByName(p.Name).Consistent(p))
}

// The identifier must carry the instance's own name, so two instances behind
// the same URL are not reported as one asset.
func TestInstanceIdentifier(t *testing.T) {
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/artifactory/instance/jfrt@01ab2c3d",
		NewArtifactoryIdentifier("jfrt@01ab2c3d"))
	assert.NotEqual(t, NewArtifactoryIdentifier("jfrt@01ab2c3d"), NewArtifactoryIdentifier("jfrt@09zy8x7w"))
}

func TestPlatformByNameReportsAnUnknownName(t *testing.T) {
	assert.Nil(t, PlatformByName("not-a-platform"))
}
