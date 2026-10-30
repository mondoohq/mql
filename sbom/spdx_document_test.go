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

// spdxDoc is the part of a rendered document these tests read: the identity
// fields the spec makes mandatory, and who the document says made it.
type spdxDoc struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
}

func renderSpdx(t *testing.T, bom *Sbom) (spdxDoc, string) {
	t.Helper()
	var b strings.Builder
	require.NoError(t, New(FormatSpdxJSON).Render(&b, bom))

	var doc spdxDoc
	require.NoError(t, json.Unmarshal([]byte(b.String()), &doc))
	return doc, b.String()
}

func bomWithGenerator(g *Generator) *Sbom {
	return &Sbom{
		Asset:     &Asset{Name: "my-host", Platform: &Platform{Name: "linux"}},
		Generator: g,
		Packages:  []*Package{{Name: "p", Version: "1"}},
	}
}

// A creator carrying no value takes the whole document down. The library
// marshals it to zero bytes, which is not JSON, so one blank entry fails the
// render with `unexpected end of JSON input` rather than producing a document
// missing one line. A generator with no vendor is the case that hit it, and an
// imported document rarely names one.
func TestSPDXRendersWhateverTheGeneratorDoesNotName(t *testing.T) {
	for _, c := range []struct {
		name string
		gen  *Generator
		want []string
	}{
		{
			name: "vendor and tool",
			gen:  &Generator{Name: "mql", Version: "1.2.3", Vendor: "Mondoo, Inc."},
			want: []string{"Organization: Mondoo, Inc.", "Tool: mql-1.2.3"},
		},
		{
			// The case that failed every render.
			name: "no vendor",
			gen:  &Generator{Name: "mql", Version: "1.2.3"},
			want: []string{"Tool: mql-1.2.3"},
		},
		{
			// A bare trailing "-" reads as a tool whose version is the empty
			// string rather than one that did not state a version.
			name: "no version",
			gen:  &Generator{Name: "mql", Vendor: "Mondoo, Inc."},
			want: []string{"Organization: Mondoo, Inc.", "Tool: mql"},
		},
		{
			name: "no tool",
			gen:  &Generator{Vendor: "Mondoo, Inc."},
			want: []string{"Organization: Mondoo, Inc."},
		},
		{
			// Cardinality is 1..*, so something has to be said. "anonymous" is
			// the spec's own word for a creator that cannot be named.
			name: "names nobody",
			gen:  &Generator{},
			want: []string{"Organization: anonymous"},
		},
		{
			name: "no generator at all",
			gen:  nil,
			want: []string{"Organization: anonymous"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc, _ := renderSpdx(t, bomWithGenerator(c.gen))
			assert.Equal(t, c.want, doc.CreationInfo.Creators)
		})
	}
}

// The three fields below are mandatory in SPDX 2.x and were rendered as "",
// which made every document this renderer produced invalid.
func TestSPDXCarriesTheIdentityTheSpecRequires(t *testing.T) {
	doc, _ := renderSpdx(t, bomWithGenerator(&Generator{Name: "mql", Version: "1.2.3", Vendor: "Mondoo, Inc."}))

	// Fixed by the spec: a document's own metadata is CC0-1.0 whatever it
	// describes.
	assert.Equal(t, "CC0-1.0", doc.DataLicense)
	assert.Equal(t, "my-host", doc.Name)
	assert.True(t, strings.HasPrefix(doc.DocumentNamespace, "https://mondoo.com/spdx/my-host-"),
		"documentNamespace = %q", doc.DocumentNamespace)

	t.Run("a document whose asset does not name itself is still named", func(t *testing.T) {
		doc, _ := renderSpdx(t, &Sbom{
			Asset:     &Asset{Platform: &Platform{Name: "linux"}},
			Generator: &Generator{Name: "mql"},
			Packages:  []*Package{{Name: "p"}},
		})
		assert.NotEmpty(t, doc.Name)
		assert.NotEmpty(t, doc.DocumentNamespace)
	})

	// Uniqueness is per document, not per asset: scanning the same host twice
	// produces two documents, and a consumer holding both has to be able to
	// tell which package list it is looking at.
	t.Run("two documents about one asset do not share an identity", func(t *testing.T) {
		bom := bomWithGenerator(&Generator{Name: "mql"})
		first, _ := renderSpdx(t, bom)
		second, _ := renderSpdx(t, bom)
		assert.NotEqual(t, first.DocumentNamespace, second.DocumentNamespace)
	})
}

// Creators are told apart by their type, not their position. Reading
// creators[0] took this renderer's own Organization as the tool's name, which
// dropped the vendor and version and left a generator whose empty vendor failed
// the next render -- so mql could not read back a document it had just written.
func TestSPDXReadsBackTheDocumentItWrote(t *testing.T) {
	bom := bomWithGenerator(&Generator{Name: "mql", Version: "1.2.3", Vendor: "Mondoo, Inc."})
	_, out := renderSpdx(t, bom)

	h := New(FormatSpdxJSON).(*Spdx)
	back, err := h.Parse(strings.NewReader(out))
	require.NoError(t, err)

	assert.Equal(t, "mql", back.GetGenerator().GetName())
	assert.Equal(t, "1.2.3", back.GetGenerator().GetVersion())
	assert.Equal(t, "Mondoo, Inc.", back.GetGenerator().GetVendor())
	assert.Equal(t, "my-host", back.GetAsset().GetName())

	// The render that used to fail.
	var b strings.Builder
	require.NoError(t, New(FormatSpdxJSON).Render(&b, back))
}

func TestSPDXReadsCreatorsThatSayLittle(t *testing.T) {
	parse := func(t *testing.T, creators string) *Sbom {
		t.Helper()
		doc := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",` +
			`"name":"x","documentNamespace":"https://example.com/x",` +
			`"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":[` + creators + `]},"packages":[]}`
		h := New(FormatSpdxJSON).(*Spdx)
		bom, err := h.Parse(strings.NewReader(doc))
		require.NoError(t, err)
		return bom
	}

	// A document listing no creators is not valid, but it parses, and indexing
	// into an empty list to find out panicked the reader.
	t.Run("no creators is not a panic", func(t *testing.T) {
		bom := parse(t, "")
		assert.Empty(t, bom.GetGenerator().GetName())
		assert.Empty(t, bom.GetGenerator().GetVendor())
	})

	// Position says nothing: the tool is the entry typed Tool wherever it sits.
	t.Run("the tool is found after the organization", func(t *testing.T) {
		bom := parse(t, `"Organization: ExampleCorp","Tool: syft-v0.9.0"`)
		assert.Equal(t, "syft", bom.GetGenerator().GetName())
		assert.Equal(t, "v0.9.0", bom.GetGenerator().GetVersion())
		assert.Equal(t, "ExampleCorp", bom.GetGenerator().GetVendor())
	})

	t.Run("and before it", func(t *testing.T) {
		bom := parse(t, `"Tool: syft-v0.9.0","Organization: ExampleCorp"`)
		assert.Equal(t, "syft", bom.GetGenerator().GetName())
		assert.Equal(t, "ExampleCorp", bom.GetGenerator().GetVendor())
	})

	// "anonymous" is a placeholder for a creator that could not be named, so
	// carrying it would report somebody called that to every other format.
	t.Run("anonymous is not a vendor", func(t *testing.T) {
		bom := parse(t, `"Organization: anonymous","Tool: mql-1.2.3"`)
		assert.Empty(t, bom.GetGenerator().GetVendor())
		assert.Equal(t, "mql", bom.GetGenerator().GetName())
	})
}

// The spec's tool format is ambiguous, because a tool identifier may itself
// contain a hyphen. Splitting unconditionally turns "my-tool" into a tool
// called "my" at version "tool".
func TestSPDXSplitsAToolFromItsVersionOnlyWhenThereIsOne(t *testing.T) {
	for _, c := range []struct{ in, name, version string }{
		{"mql-1.2.3", "mql", "1.2.3"},
		{"syft-v0.9.0", "syft", "v0.9.0"},
		{"cyclonedx-gomod-v1.4.0", "cyclonedx-gomod", "v1.4.0"},
		{"mql", "mql", ""},
		{"my-tool", "my-tool", ""},
		{"-1.0", "-1.0", ""},
	} {
		t.Run(c.in, func(t *testing.T) {
			name, version := spdxSplitTool(c.in)
			assert.Equal(t, c.name, name)
			assert.Equal(t, c.version, version)
		})
	}
}

// Splitting a tool identifier cannot be got right from the string alone: a tool
// genuinely called "log4j-2" is indistinguishable from version 2 of "log4j".
// What has to hold instead is that the document does not drift -- rejoining
// whatever the split produced reproduces the identifier exactly, so a document
// passed through mql any number of times still names the tool it named at the
// start. That is the property the old reader broke, and it is stronger than
// asserting any particular split, because it holds even where the split is
// arguable.
func TestSPDXToolIdentifierSurvivesARoundTrip(t *testing.T) {
	for _, tool := range []string{
		"mql-1.2.3",
		"my-tool",
		"cyclonedx-gomod-v1.4.0",
		// Arguable split, exact round trip: name "log4j", version "2".
		"log4j-2",
		"tool-2-beta",
		"trivy-0.50.1",
		"mql",
		"v1.0",
		"a-b-1.0-2.0",
		// Degenerate shapes that must still come back unchanged.
		"-1.0",
		"mql-",
	} {
		t.Run(tool, func(t *testing.T) {
			name, version := spdxSplitTool(tool)
			assert.Equal(t, tool, spdxToolIdentifier(&Generator{Name: name, Version: version}))
		})
	}
}

// The same property through the real renderer and reader rather than the two
// helpers, since that is the path a document actually takes.
func TestSPDXDocumentSurvivesRepeatedRoundTrips(t *testing.T) {
	bom := bomWithGenerator(&Generator{Name: "cyclonedx-gomod", Version: "v1.4.0", Vendor: "ExampleCorp"})
	h := New(FormatSpdxJSON).(*Spdx)

	for pass := range 3 {
		_, out := renderSpdx(t, bom)

		var doc spdxDoc
		require.NoError(t, json.Unmarshal([]byte(out), &doc))
		assert.Equal(t, []string{"Organization: ExampleCorp", "Tool: cyclonedx-gomod-v1.4.0"},
			doc.CreationInfo.Creators, "creators drifted on pass %d", pass)

		back, err := h.Parse(strings.NewReader(out))
		require.NoError(t, err)
		bom = back
	}
}

// The version test is a hand-rolled check rather than a pattern, so its edges
// are pinned directly: a bare "v" is not a version, and a "v" only counts when
// a digit follows it.
func TestSPDXLooksLikeVersion(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"1", true},
		{"9", true},
		{"v1", true},
		{"v0", true},
		{"0.50.1", true},
		{"v1.2.3", true},
		{"", false},
		{"v", false},
		{"vv1", false},
		{"a1", false},
		{"beta", false},
		{"tool", false},
		{"V1", false},
		{"v-1", false},
		{" 1", false},
		// Multibyte input must not be read a byte at a time into a false
		// positive: this is an Arabic-Indic one, not an ASCII digit.
		{"\u0661", false},
	} {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, spdxLooksLikeVersion(c.in))
		})
	}
}

// A namespace has to be different every time and must never be the reason a
// render fails: the uniquifier falls back to the clock rather than panicking
// when the entropy source cannot be read.
func TestSPDXNamespaceSuffixIsUniqueAndNeverPanics(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		s := spdxNamespaceSuffix()
		require.NotEmpty(t, s)
		require.False(t, seen[s], "suffix repeated: %q", s)
		seen[s] = true
	}
}
