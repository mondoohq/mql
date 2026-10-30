// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The SPDX decoder is an importer: the document it reads was produced by
// somebody else, and what it says about licensing cannot be recovered from
// anywhere else in the file. It read each package's name, version, identifiers
// and file evidence and dropped the rest.
//
// #10597 fixed this for the Protobom decoder. This asserts through
// DefaultMultiDecoder, which is what consumers call and which routes SPDX to
// *this* decoder -- so the earlier fix reached none of them, and a test calling
// only the Protobom decoder would not have noticed.
func TestSpdxDecoderReadsLicensing(t *testing.T) {
	f, err := os.Open("testdata/licensing.spdx.json")
	require.NoError(t, err)
	defer f.Close()

	bom, err := DefaultMultiDecoder().Parse(f)
	require.NoError(t, err)

	byName := map[string]*Package{}
	for _, p := range bom.Packages {
		byName[p.Name] = p
	}

	t.Run("declared and concluded are told apart by the field they came from", func(t *testing.T) {
		p := byName["declared-and-concluded"]
		require.NotNil(t, p)
		require.Len(t, p.Licenses, 2)

		assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, p.Licenses[0].GetAcquisition())
		assert.Equal(t, "MIT", p.Licenses[0].GetSpdxId())

		assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED, p.Licenses[1].GetAcquisition())
		assert.Equal(t, "AGPL-3.0-only", p.Licenses[1].GetSpdxId())

		// Zero, not 1.0: SPDX carries no score, and the model spells "nobody
		// measured this" as 0. Reporting full confidence would rank an imported
		// conclusion nobody scored alongside one that scored perfectly.
		assert.Zero(t, p.Licenses[1].GetConfidence())

		// The declared entry wins the legacy scalar, so a consumer that has not
		// migrated to the list still sees a license.
		assert.Equal(t, "MIT", p.License)

		assert.Equal(t, []string{"Copyright (c) 2019 Example Corp"}, p.Copyright)
		assert.Equal(t, "Example Corp", p.Supplier)
	})

	t.Run("a declaration alone is enough", func(t *testing.T) {
		p := byName["declared-only"]
		require.NotNil(t, p)
		require.Len(t, p.Licenses, 1)
		assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, p.Licenses[0].GetAcquisition())
		assert.Equal(t, "Apache-2.0", p.Licenses[0].GetSpdxId())
		assert.Equal(t, "Apache-2.0", p.License)
	})

	// NOASSERTION and NONE are SPDX's two ways of saying it is not telling you.
	// Carrying either through as a license name would report a package as
	// licensed under the string "NOASSERTION", which matches nothing and reads
	// as a statement where the document made none.
	for _, name := range []string{"states-nothing", "states-none"} {
		t.Run(name+" reports no license", func(t *testing.T) {
			p := byName[name]
			require.NotNil(t, p)
			assert.Empty(t, p.Licenses)
			assert.Empty(t, p.License)
		})
	}
}

// This renderer writes a concluded value equal to the declared one where nothing
// was concluded, rather than NOASSERTION, and other SPDX producers do the same.
// Reading that back as a determination is how a round trip through our own
// output invents a claim the model never made: a package that declared MIT and
// concluded nothing returns asserting somebody concluded MIT.
func TestSPDXDecoderDoesNotReadAnEchoAsAConclusion(t *testing.T) {
	orig := &Sbom{
		Generator: &Generator{Vendor: "Mondoo, Inc", Name: "test", Version: "1"},
		Asset:     &Asset{Name: "a", Platform: &Platform{Name: "linux", Version: "1"}},
		Packages: []*Package{{
			Name: "declares-only", Version: "1.0.0", Purl: "pkg:npm/declares-only@1.0.0",
			Licenses: []*License{DeclaredLicense("MIT")},
			License:  "MIT",
		}},
	}

	var rendered strings.Builder
	require.NoError(t, New(FormatSpdxJSON).Render(&rendered, orig))
	// The echo is in the document: this is what the decoder has to interpret.
	assert.Contains(t, rendered.String(), `"licenseConcluded": "MIT"`)

	back, err := NewSPDX(FormatSpdxJSON).Parse(strings.NewReader(rendered.String()))
	require.NoError(t, err)

	var got *Package
	for _, p := range back.Packages {
		if p.Name == "declares-only" {
			got = p
		}
	}
	require.NotNil(t, got)

	require.Len(t, got.Licenses, 1, "the echoed conclusion must not become a second entry")
	assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, got.Licenses[0].GetAcquisition())
	assert.Equal(t, "MIT", got.Licenses[0].GetSpdxId())
	assert.Equal(t, "MIT", got.License)
}

// A conclusion that DISAGREES with the declaration is the case the split exists
// for, and must survive the echo check.
func TestSPDXDecoderKeepsAConclusionThatDisagrees(t *testing.T) {
	doc := `{
  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
  "name": "disagreeing", "documentNamespace": "https://mondoo.com/spdx/d",
  "creationInfo": { "created": "2026-08-30T09:00:00Z", "creators": ["Tool: fixture-1"] },
  "packages": [{
    "name": "disagrees", "SPDXID": "SPDXRef-P1", "versionInfo": "1.0.0",
    "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
    "licenseDeclared": "MIT", "licenseConcluded": "AGPL-3.0-only"
  }]
}`
	back, err := NewSPDX(FormatSpdxJSON).Parse(strings.NewReader(doc))
	require.NoError(t, err)
	require.Len(t, back.Packages, 1)

	licenses := back.Packages[0].Licenses
	require.Len(t, licenses, 2)
	assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, licenses[0].GetAcquisition())
	assert.Equal(t, "MIT", licenses[0].GetSpdxId())
	assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED, licenses[1].GetAcquisition())
	assert.Equal(t, "AGPL-3.0-only", licenses[1].GetSpdxId())

	// The scalar still takes the declared entry.
	assert.Equal(t, "MIT", back.Packages[0].License)
}

// A document that concludes without declaring is not an echo: the conclusion is
// the only thing it states, and dropping it would lose the license entirely.
func TestSPDXDecoderKeepsAConclusionWithNoDeclaration(t *testing.T) {
	doc := `{
  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
  "name": "concluded-only", "documentNamespace": "https://mondoo.com/spdx/c",
  "creationInfo": { "created": "2026-08-30T09:00:00Z", "creators": ["Tool: fixture-1"] },
  "packages": [{
    "name": "concluded-only", "SPDXID": "SPDXRef-P1", "versionInfo": "1.0.0",
    "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
    "licenseDeclared": "NOASSERTION", "licenseConcluded": "Apache-2.0"
  }]
}`
	back, err := NewSPDX(FormatSpdxJSON).Parse(strings.NewReader(doc))
	require.NoError(t, err)
	require.Len(t, back.Packages, 1)

	licenses := back.Packages[0].Licenses
	require.Len(t, licenses, 1)
	assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED, licenses[0].GetAcquisition())
	assert.Equal(t, "Apache-2.0", licenses[0].GetSpdxId())
	assert.Equal(t, "Apache-2.0", back.Packages[0].License, "the scalar falls back to the conclusion")
}
