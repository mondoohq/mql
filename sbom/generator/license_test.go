// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/sbom"
)

// The whole path, from the report JSON through to the SBOM: the struct tag on
// BomPackage, the mapping in the generator, and the model entry. A unit test on
// the mapper alone would miss the tag, which is the half that fails silently --
// a mistyped `json:"license"` yields a zero value, not an error.
func TestLicenseReachesTheSbom(t *testing.T) {
	report, err := LoadReport("testdata/licenses.json")
	require.NoError(t, err)

	boms := GenerateBom(report)
	require.Len(t, boms, 1)
	pkgs := boms[0].Packages

	t.Run("a bare identifier lands in spdx_id", func(t *testing.T) {
		pkg := findProtoPkg(pkgs, "busybox")
		require.NotNil(t, pkg)

		// The legacy scalar keeps being written. Nothing populates it from the
		// list, so a consumer that has not migrated would see nothing without it.
		assert.Equal(t, "GPL-2.0-only", pkg.License) //nolint:staticcheck // SA1019: that the legacy scalar is STILL written is the assertion

		require.Len(t, pkg.Licenses, 1)
		l := pkg.Licenses[0]
		assert.Equal(t, "GPL-2.0-only", l.GetSpdxId())
		assert.Empty(t, l.GetExpression())
		assert.Empty(t, l.GetName())
		assert.Equal(t, sbom.LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, l.GetAcquisition())
		assert.Equal(t, 1.0, l.GetConfidence())
	})

	// An expression in the id slot is the malformed document the three mutually
	// exclusive fields exist to prevent, so this is the case that matters most.
	t.Run("an expression lands in expression, not spdx_id", func(t *testing.T) {
		pkg := findProtoPkg(pkgs, "dual-licensed")
		require.NotNil(t, pkg)

		require.Len(t, pkg.Licenses, 1)
		l := pkg.Licenses[0]
		assert.Equal(t, "MIT OR Apache-2.0", l.GetExpression())
		assert.Empty(t, l.GetSpdxId())
		assert.Empty(t, l.GetName())
	})

	t.Run("free text lands in name", func(t *testing.T) {
		pkg := findProtoPkg(pkgs, "freetext")
		require.NotNil(t, pkg)

		require.Len(t, pkg.Licenses, 1)
		l := pkg.Licenses[0]
		assert.Equal(t, "see the LICENSE file", l.GetName())
		assert.Empty(t, l.GetSpdxId())
		assert.Empty(t, l.GetExpression())
	})

	// A package that declared nothing gets no entry at all. An entry naming no
	// license asserts a licensing fact the producer does not have, and a
	// consumer cannot tell it apart from a real determination.
	t.Run("a package that declared nothing carries no entry", func(t *testing.T) {
		pkg := findProtoPkg(pkgs, "undeclared")
		require.NotNil(t, pkg)

		assert.Empty(t, pkg.License) //nolint:staticcheck // SA1019: that the legacy scalar is STILL written is the assertion
		assert.Empty(t, pkg.Licenses)
	})
}

// languagePackages is what the ecosystems share, so a license dropped there is
// dropped for seventeen of them at once.
func TestLanguagePackagesCarryTheLicense(t *testing.T) {
	out := languagePackages([]BomPackage{
		{Name: "a", Version: "1", License: "MIT"},
		{Name: "b", Version: "2"},
	}, "npm")
	require.Len(t, out, 2)

	assert.Equal(t, "MIT", out[0].License) //nolint:staticcheck // SA1019: that the legacy scalar is STILL written is the assertion
	require.Len(t, out[0].Licenses, 1)
	assert.Equal(t, "MIT", out[0].Licenses[0].GetSpdxId())
	assert.Equal(t, "npm", out[0].Type)

	assert.Empty(t, out[1].License) //nolint:staticcheck // SA1019: that the legacy scalar is STILL written is the assertion
	assert.Empty(t, out[1].Licenses)
}

// GithubActions, Jenkins and Wordpress packages were built by hand-written
// loops that never mapped Cpes, so a CPE the query reported was dropped. They
// go through the shared constructor now, which is the whole point of having
// one: the three were identical to it apart from the field they were missing.
func TestGithubActionPackagesCarryCpesAndLicense(t *testing.T) {
	report, err := LoadReport("testdata/licenses.json")
	require.NoError(t, err)

	boms := GenerateBom(report)
	require.Len(t, boms, 1)

	pkg := findProtoPkg(boms[0].Packages, "actions/checkout")
	require.NotNil(t, pkg)
	assert.Equal(t, "github-action", pkg.Type)
	assert.Equal(t, []string{"cpe:2.3:a:actions:checkout:4.2.2:*:*:*:*:*:*:*"}, pkg.Cpes)

	require.Len(t, pkg.Licenses, 1)
	assert.Equal(t, "MIT", pkg.Licenses[0].GetSpdxId())
}
