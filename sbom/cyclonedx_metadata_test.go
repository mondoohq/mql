// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cdxMetadataDoc is the part of a rendered document these tests read: who the
// document says made it, and what it says it is about.
type cdxMetadataDoc struct {
	Metadata struct {
		Tools *struct {
			Components *[]struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Author  string `json:"author"`
			} `json:"components"`
		} `json:"tools"`
		Component *struct {
			BOMRef string `json:"bom-ref"`
			Name   string `json:"name"`
			Type   string `json:"type"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Name string `json:"name"`
	} `json:"components"`
}

func renderCdx(t *testing.T, bom *Sbom) cdxMetadataDoc {
	t.Helper()
	var b strings.Builder
	require.NoError(t, New(FormatCycloneDxJSON).Render(&b, bom))

	var doc cdxMetadataDoc
	require.NoError(t, json.Unmarshal([]byte(b.String()), &doc))
	return doc
}

// The CycloneDX renderer read Generator and Asset straight through, so a BOM
// that did not carry them took the whole render down with a nil dereference
// rather than producing a document missing some metadata. Every other renderer
// in this package survives the same input, which is what made this one wrong
// rather than merely strict.
//
// The two are independent -- a BOM missing one is not usually missing the other
// -- so they get separate cases rather than one "nothing is set" case standing
// in for both.
func TestCycloneDXRendersABomThatNamesNoMetadata(t *testing.T) {
	pkgs := []*Package{{Name: "p", Version: "1"}}

	t.Run("no generator", func(t *testing.T) {
		doc := renderCdx(t, &Sbom{Asset: &Asset{Name: "h"}, Packages: pkgs})

		// A component's name is required by the schema, so a generator naming
		// no tool is rendered as no tool rather than as one called "".
		assert.Nil(t, doc.Metadata.Tools)
		// The rest of the document is unaffected.
		require.NotNil(t, doc.Metadata.Component)
		assert.Equal(t, "h", doc.Metadata.Component.Name)
		require.Len(t, doc.Components, 1)
		assert.Equal(t, "p", doc.Components[0].Name)
	})

	t.Run("no asset", func(t *testing.T) {
		doc := renderCdx(t, &Sbom{
			Generator: &Generator{Name: "mql", Version: "1.2.3", Vendor: "Mondoo, Inc."},
			Packages:  pkgs,
		})

		// The root component stays: this package's own reader rejects a
		// document without one ("not a valid cyclone dx BOM"), so dropping it
		// would trade a panic for a document mql cannot read back. It is named
		// instead, since the schema requires a name.
		require.NotNil(t, doc.Metadata.Component)
		assert.Equal(t, unnamedSubject, doc.Metadata.Component.Name)
		assert.Equal(t, "root:"+unnamedSubject, doc.Metadata.Component.BOMRef)

		require.NotNil(t, doc.Metadata.Tools)
		require.NotNil(t, doc.Metadata.Tools.Components)
		require.Len(t, *doc.Metadata.Tools.Components, 1)
		assert.Equal(t, "mql", (*doc.Metadata.Tools.Components)[0].Name)
	})

	t.Run("neither", func(t *testing.T) {
		doc := renderCdx(t, &Sbom{Packages: pkgs})
		assert.Nil(t, doc.Metadata.Tools)
		require.NotNil(t, doc.Metadata.Component)
		assert.Equal(t, unnamedSubject, doc.Metadata.Component.Name)
		require.Len(t, doc.Components, 1)
	})

	// A BOM with no packages either: nothing to describe is still a document,
	// not a crash.
	t.Run("an empty bom", func(t *testing.T) {
		doc := renderCdx(t, &Sbom{})
		require.NotNil(t, doc.Metadata.Component)
		assert.Equal(t, unnamedSubject, doc.Metadata.Component.Name)
	})
}

// Whatever a BOM omits, every format has to produce something. CycloneDX was
// the only renderer that did not, and the gap is easiest to reintroduce by
// adding a metadata read to one of them, so the property is pinned across all
// of them rather than only the one that was broken.
func TestEveryRendererSurvivesAMetadatalessBom(t *testing.T) {
	for _, c := range []struct {
		name string
		bom  *Sbom
	}{
		{"no generator", &Sbom{Asset: &Asset{Name: "h", Platform: &Platform{Name: "linux"}}}},
		{"no platform", &Sbom{Asset: &Asset{Name: "h"}, Generator: &Generator{Name: "mql"}}},
		{"no asset", &Sbom{Generator: &Generator{Name: "mql"}}},
		{"nothing at all", &Sbom{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, format := range []string{
				FormatCycloneDxJSON,
				FormatCycloneDxXML,
				FormatSpdxJSON,
				FormatSpdxTagValue,
				FormatList,
				FormatJson,
			} {
				t.Run(format, func(t *testing.T) {
					c.bom.Packages = []*Package{{Name: "p", Version: "1"}}
					var b strings.Builder
					// Neither a panic nor an error: assert.NotPanics reports the
					// panic as a failure rather than taking the test binary down.
					require.NotPanics(t, func() {
						require.NoError(t, New(format).Render(&b, c.bom))
					})
					assert.NotEmpty(t, b.String())
				})
			}
		})
	}
}

// The fallback name is shared with the SPDX renderer, so the two documents
// describing one nameless BOM agree about what its subject is called. They
// answer the same question from the same empty field, and a reader holding both
// should not have to reconcile two different answers.
func TestBothRenderersAgreeOnAnUnnamedSubject(t *testing.T) {
	bom := &Sbom{Generator: &Generator{Name: "mql"}, Packages: []*Package{{Name: "p"}}}

	cdx := renderCdx(t, bom)
	require.NotNil(t, cdx.Metadata.Component)

	var b strings.Builder
	require.NoError(t, New(FormatSpdxJSON).Render(&b, bom))
	var spdxDoc struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal([]byte(b.String()), &spdxDoc))

	assert.Equal(t, spdxDoc.Name, cdx.Metadata.Component.Name)
}
