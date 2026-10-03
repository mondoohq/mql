// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ID=c2distro ID_LIKE=debian resolved as generic-linux in the linux family:
// packages, services, the CPE and every debian-family policy lost the lineage.
func TestDebianDerivativeKeepsTheFamily(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian-derivative.toml")
	require.NoError(t, err)
	assert.Equal(t, "c2distro", di.Name)
	assert.Equal(t, "7.1", di.Version)
	assert.Equal(t, "C2 Distro 7.1", di.Title)
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebianWithoutOsRelease(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian-no-osrelease.toml")
	require.NoError(t, err)
	assert.Equal(t, "debian", di.Name)
	assert.Equal(t, "6.0.10", di.Version)
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebianSidDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian-sid.toml")
	require.NoError(t, err)
	assert.Equal(t, "debian", di.Name)
	assert.Equal(t, "forky/sid", di.Version)
	assert.Equal(t, "forky", di.Build)
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}
