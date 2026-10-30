// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseCosPackages(t *testing.T) {
	f, err := os.Open("testdata/cos-package-info.json")
	require.NoError(t, err)
	defer f.Close()

	pf := &inventory.Platform{
		Name:    "cos",
		Version: "97",
		Arch:    "x86_64",
		Labels:  map[string]string{"distro-id": "cos"},
	}

	m, err := ParseCosPackages(pf, f)
	require.NoError(t, err)
	require.Len(t, m, 4)

	byName := map[string]Package{}
	for _, p := range m {
		byName[p.Name] = p
	}

	zlib := byName["zlib"]
	assert.Equal(t, "zlib", zlib.Name)
	assert.Equal(t, "1.2.11-r4", zlib.Version)
	assert.Equal(t, "cos", zlib.Format)
	// `pkg:cos` shape from osv-scalibr / purl-spec PR #270, with the ebuild
	// version in the @version slot and the COS image version preserved as
	// the build qualifier.
	assert.Contains(t, zlib.PUrl, "pkg:cos/zlib@1.2.11-r4")
	assert.Contains(t, zlib.PUrl, "build=16919.103.16")
	assert.Contains(t, zlib.PUrl, "distro=cos-97")
	assert.NotContains(t, zlib.PUrl, "namespace")
	assert.NotContains(t, zlib.PUrl, "pkg:cos/sys-libs/") // no namespace

	// Falls back to `version` when `ebuild_version` is missing; in that case
	// we skip the build qualifier (it would equal the version).
	ca := byName["ca-certificates"]
	assert.Equal(t, "20230311.3.96.1", ca.Version)
	assert.Contains(t, ca.PUrl, "pkg:cos/ca-certificates@20230311.3.96.1")
	assert.NotContains(t, ca.PUrl, "build=")
}

func TestParseCosPackages_NoPlatform(t *testing.T) {
	f, err := os.Open("testdata/cos-package-info.json")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseCosPackages(nil, f)
	require.NoError(t, err)
	require.Len(t, m, 4)

	byName := map[string]Package{}
	for _, p := range m {
		byName[p.Name] = p
	}

	// Without a platform we still emit a structurally-valid PURL — just no
	// distro qualifier and no arch.
	assert.Contains(t, byName["zlib"].PUrl, "pkg:cos/zlib@1.2.11-r4")
	assert.Contains(t, byName["zlib"].PUrl, "build=16919.103.16")
}
