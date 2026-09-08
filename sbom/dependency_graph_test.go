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

// TestSpdxDependencyGraphRoundTrips is the read half of TestSpdxDependencyGraph
// above, which only ever asserted that a DEPENDS_ON relationship was WRITTEN.
//
// The graph was write-only on the SPDX side: the renderer emitted every edge
// and the parser read nodes alone, so a document round-tripped through SPDX
// arrived with its packages intact and its dependency structure silently gone.
// CycloneDX kept the graph (#10659); SPDX dropped it. Against the parent commit
// this fails with an empty Dependencies.
func TestSpdxDependencyGraphRoundTrips(t *testing.T) {
	out := bytes.Buffer{}
	require.NoError(t, sbom.NewSPDX(sbom.FormatSpdxJSON).Render(&out, graphBom()))

	got, err := sbom.NewProtobom().Parse(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	require.NotNil(t, got)

	require.Len(t, got.Dependencies, 1, "the DEPENDS_ON relationship should come back as one edge")
	assert.Equal(t, "pkg:npm/app@1.0.0", got.Dependencies[0].Ref)
	assert.Equal(t, []string{"pkg:npm/left-pad@1.3.0"}, got.Dependencies[0].DependencyRefs)
}

// TestSpdxDependencyGraphReadsDependencyOf pins the inverted spelling. SPDX
// states the same fact two ways -- DEPENDS_ON and DEPENDENCY_OF -- and a
// producer may emit either, so a reader that understands only one silently
// loses half the documents in the wild. The direction matters: a dependencyOf
// edge names the DEPENDENCY as its source, so importing it unreversed would
// invert the graph and make a library depend on the application.
//
// Built through protobom rather than through the renderer, because mql's SPDX
// renderer only ever writes DEPENDS_ON.
func TestSpdxDependencyGraphReadsDependencyOf(t *testing.T) {
	doc := `{
	  "spdxVersion": "SPDX-2.3",
	  "dataLicense": "CC0-1.0",
	  "SPDXID": "SPDXRef-DOCUMENT",
	  "name": "app",
	  "documentNamespace": "https://example.com/app",
	  "creationInfo": {"created": "2026-09-08T00:00:00Z", "creators": ["Tool: test-1"]},
	  "packages": [
	    {"SPDXID": "SPDXRef-App", "name": "app", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION",
	     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/app@1.0.0"}]},
	    {"SPDXID": "SPDXRef-LeftPad", "name": "left-pad", "versionInfo": "1.3.0", "downloadLocation": "NOASSERTION",
	     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}]}
	  ],
	  "relationships": [
	    {"spdxElementId": "SPDXRef-LeftPad", "relatedSpdxElement": "SPDXRef-App", "relationshipType": "DEPENDENCY_OF"}
	  ]
	}`

	got, err := sbom.NewProtobom().Parse(strings.NewReader(doc))
	require.NoError(t, err)
	require.NotNil(t, got)

	require.Len(t, got.Dependencies, 1)
	// app depends on left-pad, NOT the reverse.
	assert.Equal(t, "pkg:npm/app@1.0.0", got.Dependencies[0].Ref)
	assert.Equal(t, []string{"pkg:npm/left-pad@1.3.0"}, got.Dependencies[0].DependencyRefs)
}

// TestCycloneDXParseKeepsTheBomRef pins the identity the `dependencies` section
// keys on.
//
// CycloneDX states edges by `bom-ref`, and a producer is free to choose one --
// a purl, a UUID, an internal id. The reader dropped `bom-ref` while keeping
// the edges verbatim, so for any producer that does not happen to use purls as
// bom-refs, every edge referenced a component the consumer could no longer
// identify. The graph parsed, and then correlated with nothing.
func TestCycloneDXParseKeepsTheBomRef(t *testing.T) {
	doc := `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"component": {"type": "application", "name": "app", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "3f2504e0-4f89-11d3-9a0c-0305e82c3301", "type": "library",
     "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    {"bom-ref": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "type": "library",
     "name": "right-pad", "version": "2.0.0", "purl": "pkg:npm/right-pad@2.0.0"}
  ],
  "dependencies": [
    {"ref": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
     "dependsOn": ["7c9e6679-7425-40de-944b-e07fc1f90ae7"]}
  ]
}`
	out, err := sbom.New(sbom.FormatCycloneDxJSON).Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byRef := map[string]*sbom.Package{}
	for _, p := range out.Packages {
		byRef[p.BomRef] = p
	}
	if len(byRef) != 2 {
		t.Fatalf("every component's bom-ref must survive the read, got %v", byRef)
	}
	// The edge is only usable if its endpoints resolve to components.
	if len(out.Dependencies) != 1 {
		t.Fatalf("expected the one dependency entry, got %d", len(out.Dependencies))
	}
	from, ok := byRef[out.Dependencies[0].Ref]
	if !ok {
		t.Fatalf("edge source %q resolves to no component", out.Dependencies[0].Ref)
	}
	if from.Purl != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("edge source resolved to %q", from.Purl)
	}
	to, ok := byRef[out.Dependencies[0].DependencyRefs[0]]
	if !ok {
		t.Fatalf("edge target %q resolves to no component", out.Dependencies[0].DependencyRefs[0])
	}
	if to.Purl != "pkg:npm/right-pad@2.0.0" {
		t.Errorf("edge target resolved to %q", to.Purl)
	}
}

// TestCycloneDXRoundTripPreservesTheProducersRefs is the second half of keeping
// bom-ref: a document read and written back keeps the identities it arrived
// with, rather than having every ref rewritten to a purl. Anything holding a
// reference INTO the document -- an attestation, a VEX statement, a reviewer's
// note -- still resolves afterwards.
func TestCycloneDXRoundTripPreservesTheProducersRefs(t *testing.T) {
	doc := `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"component": {"type": "application", "name": "app", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "3f2504e0-4f89-11d3-9a0c-0305e82c3301", "type": "library",
     "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}
  ]
}`
	in, err := sbom.New(sbom.FormatCycloneDxJSON).Parse(strings.NewReader(doc))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, sbom.New(sbom.FormatCycloneDxJSON).Render(&buf, in))
	assert.Contains(t, buf.String(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"the producer's bom-ref must survive a render, not be rewritten to a purl")
}
