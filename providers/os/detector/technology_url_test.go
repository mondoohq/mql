// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestAddTechnologyUrl(t *testing.T) {
	t.Run("name and version set", func(t *testing.T) {
		pf := &inventory.Platform{
			Name:    "debian",
			Version: "12.15",
			Family:  []string{"debian", "linux", "unix", "os"},
		}
		addTechnologyUrl(pf)

		assert.Equal(t, []string{"os", "linux", "debian", "12.15"}, pf.TechnologyUrlSegments)
		assert.Equal(t, "debian", pf.Name)
		assert.Equal(t, "12.15", pf.Version)
	})

	t.Run("no version, build set", func(t *testing.T) {
		pf := &inventory.Platform{
			Name:   "arch",
			Build:  "rolling",
			Family: []string{"arch", "linux", "unix", "os"},
		}
		addTechnologyUrl(pf)

		// the URL still gets a placeholder segment ...
		assert.Equal(t, []string{"os", "linux", "arch", "unknown"}, pf.TechnologyUrlSegments)
		// ... but the platform itself keeps reporting that it has no version,
		// so consumers can fall back to the build id.
		assert.Equal(t, "arch", pf.Name)
		assert.Empty(t, pf.Version)
		assert.Equal(t, "rolling", pf.Build)
	})

	t.Run("neither name nor version", func(t *testing.T) {
		pf := &inventory.Platform{}
		addTechnologyUrl(pf)

		assert.Equal(t, []string{"os", "other", "unknown", "unknown"}, pf.TechnologyUrlSegments)
		assert.Empty(t, pf.Name)
		assert.Empty(t, pf.Version)
	})

	t.Run("container image kind", func(t *testing.T) {
		pf := &inventory.Platform{
			Name:    "alpine",
			Version: "3.20",
			Kind:    "container-image",
			Family:  []string{"alpine", "linux", "unix", "os"},
		}
		addTechnologyUrl(pf)

		assert.Equal(t,
			[]string{"container", "container-image", "linux", "alpine", "3.20"},
			pf.TechnologyUrlSegments)
		assert.Equal(t, "3.20", pf.Version)
	})

	t.Run("nil platform", func(t *testing.T) {
		assert.NotPanics(t, func() { addTechnologyUrl(nil) })
	})
}

// Arch has no VERSION_ID in /etc/os-release, only BUILD_ID=rolling. The
// detection run must leave the version empty instead of reporting the URL
// placeholder as the asset's version.
func TestDetectOSKeepsRollingReleaseVersionEmpty(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		name    string
		build   string
	}{
		{fixture: "./testdata/detect-arch-vm.toml", name: "arch", build: "rolling"},
		{fixture: "./testdata/detect-endeavouros.toml", name: "endeavouros", build: "rolling"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(tc.fixture))
			require.NoError(t, err)

			pf, ok := DetectOS(conn)
			require.True(t, ok)
			require.NotNil(t, pf)

			assert.Equal(t, tc.name, pf.Name)
			assert.Empty(t, pf.Version, "rolling release has no version")
			assert.Equal(t, tc.build, pf.Build)
			assert.Equal(t, []string{"os", "linux", tc.name, "unknown"}, pf.TechnologyUrlSegments)
		})
	}
}
