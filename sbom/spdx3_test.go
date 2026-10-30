// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom_test

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func parseFile(t *testing.T, decoder sbom.Decoder, path string) *sbom.Sbom {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	bom, err := decoder.Parse(f)
	require.NoError(t, err)
	return bom
}

// packageSummary reduces a package to what an import has to carry across.
func packageSummary(p *sbom.Package) string {
	cpes := slices.Clone(p.Cpes)
	slices.Sort(cpes)
	return strings.Join([]string{p.Name, p.Version, p.Purl, p.Type, p.License, strings.Join(cpes, ",")}, "|")
}

// licenseSummaries lists every package's licenses with how each was acquired,
// so declared and concluded licenses are compared separately.
func licenseSummaries(bom *sbom.Sbom) []string {
	var out []string
	for _, p := range bom.Packages {
		for _, l := range p.Licenses {
			out = append(out, p.Name+"|"+l.Acquisition.String()+"|"+l.Expression+l.SpdxId+l.Name)
		}
	}
	slices.Sort(out)
	return out
}

func packageSummaries(bom *sbom.Sbom) []string {
	var out []string
	for _, p := range bom.Packages {
		out = append(out, packageSummary(p))
	}
	slices.Sort(out)
	return out
}

// Each SPDX 3 fixture is its SPDX 2.3 counterpart converted to SPDX 3.0.1 by
// protobom v0.6.2 and validated with spdx3-validate 0.0.7, so both describe the
// same packages and both imports must agree.
//
// Two conversion losses were repaired in the SPDX 3 files, so they carry
// everything their SPDX 2 counterparts do:
//   - alpine-319.spdx.json files its purls under the SECURITY reference
//     category, where SPDX 2.3 puts them under PACKAGE-MANAGER, and protobom
//     drops a purl filed elsewhere. alpine-319.spdx3.json was converted from a
//     copy with that category corrected.
//   - protobom keeps one CPE per package. The other five CPEs of
//     alpine-baselayout were added back to alpine-3.19.syft.spdx3.json as
//     cpe23 external identifiers.
func TestSpdx3Decoder_MatchesSpdx2(t *testing.T) {
	for name, tc := range map[string]struct {
		spdx2, spdx3 string
		packages     int
	}{
		"alpine":      {"testdata/alpine-319.spdx.json", "testdata/alpine-319.spdx3.json", 15},
		"alpine syft": {"testdata/alpine-3.19.syft.spdx.json", "testdata/alpine-3.19.syft.spdx3.json", 2},
	} {
		t.Run(name, func(t *testing.T) {
			spdx2 := parseFile(t, sbom.NewSPDX(sbom.FormatSpdxJSON), tc.spdx2)
			spdx3 := parseFile(t, sbom.DefaultMultiDecoder(), tc.spdx3)

			require.Len(t, spdx3.Packages, tc.packages)
			assert.Equal(t, packageSummaries(spdx2), packageSummaries(spdx3))
			assert.Equal(t, licenseSummaries(spdx2), licenseSummaries(spdx3))

			assert.NotEmpty(t, spdx3.Asset.Name)
			assert.Equal(t, spdx2.Asset.Name, spdx3.Asset.Name)
			assert.Equal(t, spdx2.Asset.Platform.Name, spdx3.Asset.Platform.Name)
			assert.Equal(t, spdx2.Asset.Platform.Version, spdx3.Asset.Platform.Version)
			assert.Equal(t, spdx2.Asset.Platform.Arch, spdx3.Asset.Platform.Arch)
			assert.Equal(t, spdx2.Asset.Platform.Family, spdx3.Asset.Platform.Family)
		})
	}
}

func TestSpdx3Decoder_NoDistro(t *testing.T) {
	bom := parseFile(t, sbom.DefaultMultiDecoder(), "testdata/web-app.spdx3.json")

	assert.Equal(t, "web-app", bom.Asset.Name)
	assert.Equal(t, "spdx", bom.Asset.Platform.Name)
	assert.Equal(t, "SPDX-3.0.1", bom.Asset.Platform.Version)

	// The purl is read from the dedicated software_packageUrl property as well
	// as from an ExternalIdentifier, which alpine-319.spdx3.json uses.
	var lodash *sbom.Package
	for _, p := range bom.Packages {
		if p.Name == "lodash" {
			lodash = p
		}
	}
	require.NotNil(t, lodash)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", lodash.Purl)
	assert.Equal(t, "npm", lodash.Type)

	require.Len(t, bom.Dependencies, 1)
	assert.Len(t, bom.Dependencies[0].DependencyRefs, 1)
}

func TestSpdx3Decoder_UnsupportedVersion(t *testing.T) {
	doc := []byte(`{"@context": ["https://spdx.org/rdf/3.1/spdx-context.jsonld"], "@graph": []}`)

	_, err := sbom.DefaultMultiDecoder().Parse(bytes.NewReader(doc))
	require.Error(t, err)

	// The document is recognized, so the error says what is wrong with it
	// instead of falling through to the decoders after it.
	var recognized *sbom.RecognizedFormatError
	require.ErrorAs(t, err, &recognized)
	assert.Equal(t, "SPDX 3.1", recognized.Format)
	assert.Contains(t, err.Error(), "only SPDX 3.0.1")
	assert.False(t, errors.Is(err, sbom.ErrUnknownFormat))
}

func TestSpdx3Decoder_IgnoresOtherDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"spdx 2":         `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`,
		"other json-ld":  `{"@context": "https://schema.org", "@graph": []}`,
		"context object": `{"@context": [{"ex": "https://example.com/"}], "@graph": []}`,
		"not json":       `<bom/>`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sbom.NewSPDX3().Parse(bytes.NewReader([]byte(doc)))
			require.Error(t, err)
			var recognized *sbom.RecognizedFormatError
			assert.False(t, errors.As(err, &recognized))
		})
	}
}

func TestMultiDecoder_UnknownFormat(t *testing.T) {
	_, err := sbom.DefaultMultiDecoder().Parse(bytes.NewReader([]byte(`{"name": "not an sbom"}`)))
	require.Error(t, err)
	assert.ErrorIs(t, err, sbom.ErrUnknownFormat)
	assert.Contains(t, err.Error(), "SPDX 3.0.1 (JSON-LD)")
}
