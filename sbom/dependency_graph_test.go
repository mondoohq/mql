// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

// graphBom builds a tiny two-package SBOM with a dependency edge and a dev-scoped
// package to exercise bom_ref, the dependency graph, and scope rendering.
func graphBom() *sbom.Sbom {
	return &sbom.Sbom{
		Generator: &sbom.Generator{Name: "test", Version: "1", Vendor: "Mondoo"},
		Asset:     &sbom.Asset{Name: "app", Platform: &sbom.Platform{}},
		Packages: []*sbom.Package{
			{Name: "app", Version: "1.0.0", Type: "npm", Purl: "pkg:npm/app@1.0.0"},
			{Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0"},
			{Name: "jest", Version: "29.0.0", Type: "npm", Purl: "pkg:npm/jest@29.0.0", Scope: sbom.PackageScopeDev},
		},
		Dependencies: []*sbom.Dependency{
			{Ref: "pkg:npm/app@1.0.0", DependencyRefs: []string{"pkg:npm/left-pad@1.3.0"}},
		},
	}
}

func TestBomRefFor(t *testing.T) {
	// purl-when-present
	assert.Equal(t, "pkg:npm/left-pad@1.3.0",
		sbom.BomRefFor(&sbom.Package{Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0"}))
	// synthesized fallback when no purl
	assert.Equal(t, "npm/left-pad@1.3.0",
		sbom.BomRefFor(&sbom.Package{Name: "left-pad", Version: "1.3.0", Type: "npm"}))
	// an already-set ref wins
	assert.Equal(t, "explicit",
		sbom.BomRefFor(&sbom.Package{Name: "left-pad", Purl: "pkg:npm/left-pad@1.3.0", BomRef: "explicit"}))
}

func TestCycloneDxDependencyGraph(t *testing.T) {
	out := bytes.Buffer{}
	require.NoError(t, sbom.New(sbom.FormatCycloneDxJSON).Render(&out, graphBom()))
	data := out.String()

	// stable bom-ref (the component's purl), not a random UUID
	assert.Contains(t, data, `"bom-ref": "pkg:npm/app@1.0.0"`)
	assert.Contains(t, data, `"bom-ref": "pkg:npm/left-pad@1.3.0"`)
	// dependency graph section, referencing components by bom-ref
	assert.Contains(t, data, `"dependencies"`)
	assert.Contains(t, data, `"ref": "pkg:npm/app@1.0.0"`)
	assert.Contains(t, data, `"pkg:npm/left-pad@1.3.0"`)
	// dev-scoped package rendered as excluded scope
	assert.Contains(t, data, `"scope": "excluded"`)
}

func TestSpdxDependencyGraph(t *testing.T) {
	out := bytes.Buffer{}
	require.NoError(t, sbom.NewSPDX(sbom.FormatSpdxJSON).Render(&out, graphBom()))
	data := out.String()

	// SPDX emits a DEPENDS_ON relationship for the edge
	assert.Contains(t, data, "DEPENDS_ON")
}

const testHashHex = "c0b1fa47360f400af2aec25a91cf48de4d1a15613f709c96a140fc750cb5f3a8f1c2d2e0790755734f8d7a037269becc20f8bb1ecbfd037871ea5335acf1fde0"

// hashBom builds a one-package SBOM whose component carries an integrity digest,
// to exercise CycloneDX component.hashes / SPDX checksum rendering.
func hashBom() *sbom.Sbom {
	return &sbom.Sbom{
		Generator: &sbom.Generator{Name: "test", Version: "1", Vendor: "Mondoo"},
		Asset:     &sbom.Asset{Name: "app", Platform: &sbom.Platform{}},
		Packages: []*sbom.Package{
			{
				Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0",
				Hashes: []*sbom.Hash{{Alg: "SHA-512", Value: testHashHex}},
			},
		},
	}
}

func TestCycloneDxHashes(t *testing.T) {
	out := bytes.Buffer{}
	require.NoError(t, sbom.New(sbom.FormatCycloneDxJSON).Render(&out, hashBom()))
	data := out.String()

	// CycloneDX component.hashes: algorithm in CDX spelling, hex in `content`.
	assert.Contains(t, data, `"hashes"`)
	assert.Contains(t, data, `"alg": "SHA-512"`)
	assert.Contains(t, data, `"content": "`+testHashHex+`"`)
}

func TestCycloneDxDedupsSharedBomRef(t *testing.T) {
	// The same package present at two install locations shares a purl → must
	// render as one component, not a duplicate bom-ref (invalid CycloneDX).
	bom := &sbom.Sbom{
		Generator: &sbom.Generator{Name: "test", Version: "1", Vendor: "Mondoo"},
		Asset:     &sbom.Asset{Name: "app", Platform: &sbom.Platform{}},
		Packages: []*sbom.Package{
			{Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0"},
			{Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0"},
		},
	}
	out := bytes.Buffer{}
	require.NoError(t, sbom.New(sbom.FormatCycloneDxJSON).Render(&out, bom))
	assert.Equal(t, 1, strings.Count(out.String(), `"bom-ref": "pkg:npm/left-pad@1.3.0"`))
}

func TestSpdxDedupsSharedBomRef(t *testing.T) {
	// Two entries sharing a purl must render as one SPDX package (like CycloneDX).
	bom := &sbom.Sbom{
		Generator: &sbom.Generator{Name: "test", Version: "1", Vendor: "Mondoo"},
		Asset:     &sbom.Asset{Name: "app", Platform: &sbom.Platform{}},
		Packages: []*sbom.Package{
			{Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0"},
			{Name: "left-pad", Version: "1.3.0", Type: "npm", Purl: "pkg:npm/left-pad@1.3.0"},
		},
	}
	out := bytes.Buffer{}
	require.NoError(t, sbom.NewSPDX(sbom.FormatSpdxJSON).Render(&out, bom))
	assert.Equal(t, 1, strings.Count(out.String(), `"name": "left-pad"`))
}

func TestNewSPDXPackageIDSanitizesName(t *testing.T) {
	// A package name with a newline must not leak into the SPDX id (tag-value
	// injection). The scrub replaces any non [a-zA-Z0-9.-] with "-".
	id := string(sbom.NewSPDXPackageID(&sbom.Package{
		Type:    "npm",
		Name:    "evil\nSPDXID: SPDXRef-Injected\nRelationship:",
		Version: "1.0.0",
	}))
	assert.NotContains(t, id, "\n")
	assert.NotContains(t, id, " ")
	assert.NotContains(t, id, ":")
}

func TestSpdxHashes(t *testing.T) {
	out := bytes.Buffer{}
	require.NoError(t, sbom.NewSPDX(sbom.FormatSpdxJSON).Render(&out, hashBom()))
	data := out.String()

	// SPDX package checksum: dash-free algorithm spelling + hex value.
	assert.Contains(t, data, "SHA512")
	assert.Contains(t, data, testHashHex)
}

// TestSpdxParseKeepsPackagesWithoutAPurpose pins the import against an optional
// field. primary_package_purpose is OPTIONAL in SPDX 2.3 and most producers
// omit it -- mql's own SPDX renderer among them -- but the import keyed on it
// and dropped every package whose purpose was unstated.
//
// The failure was silent in the worst way: Render then Parse of this
// three-package SBOM returned ZERO packages, so `xgrep scan --sbom <spdx>` read
// a real document as a project with no dependencies rather than as one it could
// not interpret. Verified against the parent commit, where this returns 0.
func TestSpdxParseKeepsPackagesWithoutAPurpose(t *testing.T) {
	out := bytes.Buffer{}
	require.NoError(t, sbom.NewSPDX(sbom.FormatSpdxJSON).Render(&out, graphBom()))
	// The fixture states no purpose for any package, which is the ordinary case.
	assert.NotContains(t, out.String(), "primaryPackagePurpose")

	got, err := sbom.NewProtobom().Parse(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	require.Len(t, got.GetPackages(), 3, "every rendered package should survive the round trip")

	names := []string{}
	for _, p := range got.GetPackages() {
		names = append(names, p.GetName())
	}
	assert.ElementsMatch(t, []string{"app", "left-pad", "jest"}, names)
}
