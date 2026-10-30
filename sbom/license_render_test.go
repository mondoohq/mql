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

// The renderers dropped every package license for as long as they existed,
// because nothing asserted on one: the SBOM tests all check packages, none
// checked licenses. These tests exist so that cannot recur.

func licenseBom() *Sbom {
	return &Sbom{
		Generator: &Generator{Vendor: "Mondoo, Inc", Name: "test", Version: "1"},
		Asset:     &Asset{Name: "test-asset", Platform: &Platform{Name: "linux", Version: "1"}},
		Packages: []*Package{
			{Name: "plain-id", Version: "1.0.0", Purl: "pkg:npm/plain-id@1.0.0", License: "MIT",
				Description: "a plain MIT-licensed package"},
			{Name: "expression", Version: "1.0.0", Purl: "pkg:npm/expression@1.0.0", License: "MIT OR Apache-2.0"},
			{Name: "with-exception", Version: "1.0.0", Purl: "pkg:npm/with-exception@1.0.0",
				License: "GPL-2.0-only WITH Classpath-exception-2.0"},
			{Name: "free-text", Version: "1.0.0", Purl: "pkg:npm/free-text@1.0.0", License: "BSD-like, see LICENSE"},
			{Name: "custom-ref", Version: "1.0.0", Purl: "pkg:npm/custom-ref@1.0.0", License: "LicenseRef-Acme-Internal"},
			{Name: "undeclared", Version: "1.0.0", Purl: "pkg:npm/undeclared@1.0.0"},
		},
	}
}

func renderTo(t *testing.T, format string) string {
	t.Helper()
	var b strings.Builder
	h := New(format)
	if h == nil {
		t.Fatalf("no handler for %q", format)
	}
	if err := h.Render(&b, licenseBom()); err != nil {
		t.Fatalf("Render(%s): %v", format, err)
	}
	return b.String()
}

// TestCycloneDXEmitsLicenses covers the three mutually exclusive shapes
// CycloneDX models a license with. Choosing the wrong one fails schema
// validation, so the shape has to be decided per value rather than assumed.
func TestCycloneDXEmitsLicenses(t *testing.T) {
	var doc struct {
		Components []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Licenses    []struct {
				Expression string `json:"expression"`
				License    *struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(renderTo(t, FormatCycloneDxJSON)), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	byName := map[string]int{}
	for i, c := range doc.Components {
		byName[c.Name] = i
	}
	get := func(name string) []struct {
		Expression string `json:"expression"`
		License    *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
	} {
		i, ok := byName[name]
		if !ok {
			t.Fatalf("component %q missing from the document", name)
		}
		return doc.Components[i].Licenses
	}

	// A bare SPDX identifier goes in license.id.
	if ls := get("plain-id"); len(ls) != 1 || ls[0].License == nil || ls[0].License.ID != "MIT" {
		t.Errorf("plain-id licenses = %+v, want license.id MIT", ls)
	}
	// The component description is carried through (it was previously dropped).
	if got := doc.Components[byName["plain-id"]].Description; got != "a plain MIT-licensed package" {
		t.Errorf("plain-id description = %q, want it carried through", got)
	}
	// An expression goes in expression, never in id.
	for _, name := range []string{"expression", "with-exception"} {
		ls := get(name)
		if len(ls) != 1 || ls[0].Expression == "" {
			t.Errorf("%s licenses = %+v, want an expression", name, ls)
			continue
		}
		if ls[0].License != nil {
			t.Errorf("%s set both expression and license — they are mutually exclusive", name)
		}
	}
	// Anything else goes in license.name rather than being dropped.
	if ls := get("free-text"); len(ls) != 1 || ls[0].License == nil || ls[0].License.Name == "" {
		t.Errorf("free-text licenses = %+v, want license.name", ls)
	}
	// A custom identifier is still an identifier.
	if ls := get("custom-ref"); len(ls) != 1 || ls[0].License == nil ||
		ls[0].License.ID != "LicenseRef-Acme-Internal" {
		t.Errorf("custom-ref licenses = %+v, want license.id", ls)
	}
	// An undeclared license emits no licenses key at all, which is valid
	// CycloneDX — unlike SPDX, it has no NOASSERTION to state.
	if ls := get("undeclared"); len(ls) != 0 {
		t.Errorf("undeclared licenses = %+v, want none", ls)
	}
}

// TestSPDXEmitsLicenseFields pins the three SPDX requirements the renderer used
// to miss: a concluded value, a copyright field, and NOASSERTION rather than an
// empty string.
func TestSPDXEmitsLicenseFields(t *testing.T) {
	out := renderTo(t, FormatSpdxJSON)

	var doc struct {
		Packages []struct {
			Name            string `json:"name"`
			LicenseDeclared string `json:"licenseDeclared"`
			LicenseCncluded string `json:"licenseConcluded"`
			CopyrightText   string `json:"copyrightText"`
		} `json:"packages"`
		HasExtractedLicensingInfos []struct {
			LicenseID     string `json:"licenseId"`
			ExtractedText string `json:"extractedText"`
		} `json:"hasExtractedLicensingInfos"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, p := range doc.Packages {
		if p.LicenseDeclared == "" {
			t.Errorf("%s: licenseDeclared is empty; SPDX requires NOASSERTION", p.Name)
		}
		if p.LicenseCncluded == "" {
			t.Errorf("%s: licenseConcluded is missing", p.Name)
		}
		if p.CopyrightText == "" {
			t.Errorf("%s: copyrightText is empty; SPDX requires NOASSERTION", p.Name)
		}
		if p.Name == "undeclared" {
			if p.LicenseDeclared != "NOASSERTION" {
				t.Errorf("an undeclared license rendered as %q, want NOASSERTION", p.LicenseDeclared)
			}
		}
		if p.Name == "plain-id" && p.LicenseDeclared != "MIT" {
			t.Errorf("plain-id licenseDeclared = %q, want MIT", p.LicenseDeclared)
		}
	}

	// A LicenseRef-* identifier must be declared before it is referenced.
	if len(doc.HasExtractedLicensingInfos) != 1 {
		t.Fatalf("hasExtractedLicensingInfos = %+v, want the one LicenseRef", doc.HasExtractedLicensingInfos)
	}
	if got := doc.HasExtractedLicensingInfos[0].LicenseID; got != "LicenseRef-Acme-Internal" {
		t.Errorf("extracted license id = %q", got)
	}
	if doc.HasExtractedLicensingInfos[0].ExtractedText == "" {
		t.Error("extractedText is required and must not be empty")
	}
}

// TestLicenseContentIsDeterministic keeps a committed SBOM diffable: rendering
// the same input twice must not change what it says about licenses.
//
// It compares content rather than whole documents, because a CycloneDX BOM
// carries a fresh serialNumber and timestamp per render by design — each
// document is a distinct instance, and asserting otherwise would be asserting
// against the format.
func TestLicenseContentIsDeterministic(t *testing.T) {
	strip := func(s string) string {
		var kept []string
		for line := range strings.SplitSeq(s, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, `"serialNumber"`) || strings.HasPrefix(t, `"timestamp"`) ||
				strings.HasPrefix(t, `"created"`) || strings.HasPrefix(t, `"documentNamespace"`) {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, "\n")
	}

	for _, format := range []string{FormatCycloneDxJSON, FormatSpdxJSON} {
		first := strip(renderTo(t, format))
		for range 3 {
			if strip(renderTo(t, format)) != first {
				t.Errorf("%s content is not stable across renders", format)
				break
			}
		}
		// The licenses themselves must be in there, or the comparison is vacuous.
		if !strings.Contains(first, "MIT") {
			t.Errorf("%s output carries no license content to compare", format)
		}
	}
}

// The model extension exists for one case: a package whose own manifest
// declares one license while the files it ships say another. Flattening the two
// into a single value is what the scalar forced, and it is the error that
// matters most in a compliance document — it asserts a grant the shipped code
// does not make.

func splitLicenseBom() *Sbom {
	return &Sbom{
		Generator: &Generator{Vendor: "Mondoo, Inc", Name: "test", Version: "1"},
		Asset:     &Asset{Name: "test-asset", Platform: &Platform{Name: "linux", Version: "1"}},
		Packages: []*Package{{
			Name: "disagrees", Version: "1.0.0", Purl: "pkg:npm/disagrees@1.0.0",
			// The scalar stays populated, as the migration contract requires.
			License: "MIT",
			Licenses: []*License{
				{SpdxId: "MIT", Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, Confidence: 1},
				{
					SpdxId:      "AGPL-3.0-only",
					Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED,
					Confidence:  0.98,
					Location:    "node_modules/disagrees/LICENSE",
				},
			},
			Copyright: []string{"Copyright (c) 2019 Example Corp"},
			Supplier:  "Example Corp",
		}},
	}
}

func renderBom(t *testing.T, format string, bom *Sbom) string {
	t.Helper()
	var b strings.Builder
	h := New(format)
	if h == nil {
		t.Fatalf("no handler for %q", format)
	}
	if err := h.Render(&b, bom); err != nil {
		t.Fatalf("render %s: %v", format, err)
	}
	return b.String()
}

func TestCycloneDXSeparatesDeclaredFromConcluded(t *testing.T) {
	c := cdxComponent(t, renderBom(t, "cyclonedx-json", splitLicenseBom()), "disagrees")

	// Both licenses sit on the component, because acknowledgement tells them
	// apart. Carrying the concluded one only under evidence would leave a
	// consumer reading component.licenses believing the package is licensed as
	// it claims, in exactly the case the two disagree and the shipped text is
	// the grant.
	require.Len(t, c.Licenses, 2)

	declared := c.Licenses[0]
	require.NotNil(t, declared.License)
	assert.Equal(t, "MIT", declared.License.ID)
	assert.Equal(t, "declared", declared.License.Acknowledgement)

	concluded := c.Licenses[1]
	require.NotNil(t, concluded.License)
	assert.Equal(t, "AGPL-3.0-only", concluded.License.ID)
	assert.Equal(t, "concluded", concluded.License.Acknowledgement)

	// The confidence and the file it was read from are what separate a
	// certainty from an inference, and 1.6 has no field for either.
	props := map[string]string{}
	require.NotNil(t, concluded.License.Properties)
	for _, pr := range *concluded.License.Properties {
		props[pr.Name] = pr.Value
	}
	assert.Equal(t, "0.98", props["mondoo:license:confidence"])
	assert.Equal(t, "node_modules/disagrees/LICENSE", props["mondoo:license:location"])

	// A declared license is a statement rather than a measurement, so its
	// confidence is 1.0 by construction and saying so on every license in every
	// document would be noise.
	if declared.License.Properties != nil {
		for _, pr := range *declared.License.Properties {
			assert.NotEqual(t, "mondoo:license:confidence", pr.Name)
		}
	}

	assert.Equal(t, "Copyright (c) 2019 Example Corp", c.Copyright)
	require.NotNil(t, c.Supplier)
	assert.Equal(t, "Example Corp", c.Supplier.Name)
}

// The evidence block is a second view of what component.licenses already
// carries, so it follows the same opt-in as evidence.occurrences rather than
// being the one part of the block that appears unasked.
func TestCycloneDXEvidenceFollowsTheEvidenceOption(t *testing.T) {
	t.Run("absent by default", func(t *testing.T) {
		c := cdxComponent(t, renderBom(t, "cyclonedx-json", splitLicenseBom()), "disagrees")
		if c.Evidence != nil {
			assert.Empty(t, c.Evidence.Licenses, "evidence.licenses without WithEvidence()")
			assert.Empty(t, c.Evidence.Copyright, "evidence.copyright without WithEvidence()")
		}
		// The licensing itself is still reported; only the second view is gone.
		assert.Len(t, c.Licenses, 2)
	})

	t.Run("present when asked for", func(t *testing.T) {
		var b strings.Builder
		h := New(FormatCycloneDxJSON)
		h.ApplyOptions(WithEvidence())
		require.NoError(t, h.Render(&b, splitLicenseBom()))

		c := cdxComponent(t, b.String(), "disagrees")
		require.NotNil(t, c.Evidence)
		require.Len(t, c.Evidence.Licenses, 1)
		require.NotNil(t, c.Evidence.Licenses[0].License)
		assert.Equal(t, "AGPL-3.0-only", c.Evidence.Licenses[0].License.ID)
		require.Len(t, c.Evidence.Copyright, 1)
	})
}

type cdxLicenseChoice struct {
	License *struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Acknowledgement string `json:"acknowledgement"`
		Properties      *[]struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	} `json:"license"`
	Expression      string `json:"expression"`
	Acknowledgement string `json:"acknowledgement"`
}

type cdxComponentDoc struct {
	Name      string             `json:"name"`
	Licenses  []cdxLicenseChoice `json:"licenses"`
	Copyright string             `json:"copyright"`
	Supplier  *struct {
		Name string `json:"name"`
	} `json:"supplier"`
	Evidence *struct {
		Licenses  []cdxLicenseChoice `json:"licenses"`
		Copyright []struct {
			Text string `json:"text"`
		} `json:"copyright"`
	} `json:"evidence"`
}

// cdxComponent decodes one named component out of a rendered CycloneDX document.
func cdxComponent(t *testing.T, out, name string) cdxComponentDoc {
	t.Helper()
	var doc struct {
		Components []cdxComponentDoc `json:"components"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	for _, c := range doc.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component named %q in %d components", name, len(doc.Components))
	return cdxComponentDoc{}
}

func TestSPDXConcludedIsNotAnEchoOfDeclared(t *testing.T) {
	out := renderBom(t, "spdx-json", splitLicenseBom())
	var doc struct {
		Packages []struct {
			LicenseDeclared  string `json:"licenseDeclared"`
			LicenseConcluded string `json:"licenseConcluded"`
			CopyrightText    string `json:"copyrightText"`
			Supplier         string `json:"supplier"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(doc.Packages))
	}
	p := doc.Packages[0]
	if p.LicenseDeclared != "MIT" {
		t.Errorf("licenseDeclared = %q, want MIT", p.LicenseDeclared)
	}
	if p.LicenseConcluded != "AGPL-3.0-only" {
		t.Errorf("licenseConcluded = %q, want AGPL-3.0-only — the shipped text is the grant", p.LicenseConcluded)
	}
	if p.CopyrightText != "Copyright (c) 2019 Example Corp" {
		t.Errorf("copyrightText = %q", p.CopyrightText)
	}
	if !strings.Contains(p.Supplier, "Example Corp") {
		t.Errorf("supplier = %q", p.Supplier)
	}
}

// TestLegacyScalarStillRenders is the migration contract: a producer that has
// not adopted the structured list renders exactly as it did before.
func TestLegacyScalarStillRenders(t *testing.T) {
	cdx := renderTo(t, "cyclonedx-json")
	for _, want := range []string{`"MIT"`, `"MIT OR Apache-2.0"`, `"BSD-like, see LICENSE"`} {
		if !strings.Contains(cdx, want) {
			t.Errorf("cyclonedx output lost %s", want)
		}
	}
	spdxOut := renderTo(t, "spdx-json")
	if !strings.Contains(spdxOut, "LicenseRef-Acme-Internal") {
		t.Error("spdx output lost the LicenseRef identifier")
	}
}

// TestSPDXConcludedFallsBackToDeclared: with nothing concluded, echoing the
// declared value is the honest reading — but it must be the declared value,
// not NOASSERTION, or a document loses a license it was told about.
func TestSPDXConcludedFallsBackToDeclared(t *testing.T) {
	out := renderTo(t, "spdx-json")
	var doc struct {
		Packages []struct {
			Name             string `json:"name"`
			LicenseDeclared  string `json:"licenseDeclared"`
			LicenseConcluded string `json:"licenseConcluded"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p.Name == "plain-id" && (p.LicenseDeclared != "MIT" || p.LicenseConcluded != "MIT") {
			t.Errorf("plain-id: declared=%q concluded=%q, want MIT for both", p.LicenseDeclared, p.LicenseConcluded)
		}
		if p.Name == "undeclared" && p.LicenseConcluded != "NOASSERTION" {
			t.Errorf("undeclared: concluded=%q, want NOASSERTION", p.LicenseConcluded)
		}
	}
}

// An SPDX license field holds a license *expression*, and that constrains what
// may go in it: an identifier from the SPDX list, a LicenseRef-* defined in the
// document, NONE, or NOASSERTION. A free-form name — which is exactly what
// License.name exists to carry — is none of those, so it needs encoding rather
// than passing through.

// spdxPackages decodes just the license-bearing fields of an SPDX render.
func spdxPackages(t *testing.T, pkgs ...*Package) (map[string]struct{ Declared, Concluded string }, map[string]string) {
	t.Helper()
	bom := &Sbom{
		Generator: &Generator{Vendor: "Mondoo, Inc", Name: "test", Version: "1"},
		Asset:     &Asset{Name: "test-asset", Platform: &Platform{Name: "linux", Version: "1"}},
		Packages:  pkgs,
	}
	var doc struct {
		Packages []struct {
			Name             string `json:"name"`
			LicenseDeclared  string `json:"licenseDeclared"`
			LicenseConcluded string `json:"licenseConcluded"`
		} `json:"packages"`
		HasExtractedLicensingInfos []struct {
			LicenseID   string `json:"licenseId"`
			LicenseName string `json:"name"`
		} `json:"hasExtractedLicensingInfos"`
	}
	if err := json.Unmarshal([]byte(renderBom(t, FormatSpdxJSON, bom)), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	byName := map[string]struct{ Declared, Concluded string }{}
	for _, p := range doc.Packages {
		byName[p.Name] = struct{ Declared, Concluded string }{p.LicenseDeclared, p.LicenseConcluded}
	}
	refs := map[string]string{}
	for _, e := range doc.HasExtractedLicensingInfos {
		refs[e.LicenseID] = e.LicenseName
	}
	return byName, refs
}

func declaredNamed(name string, licenses ...*License) *Package {
	for _, l := range licenses {
		if l.Acquisition == LicenseAcquisition_LICENSE_ACQUISITION_UNSPECIFIED {
			l.Acquisition = LicenseAcquisition_LICENSE_ACQUISITION_DECLARED
		}
	}
	return &Package{
		Name: name, Version: "1.0.0", Purl: "pkg:npm/" + name + "@1.0.0",
		Licenses: licenses,
	}
}

// TestSPDXFreeFormNameBecomesLicenseRef: a name that is not an identifier is
// emitted as one the document defines, and the original text survives as the
// definition's name — otherwise the reader has a reference to something the
// document never says the meaning of.
func TestSPDXFreeFormNameBecomesLicenseRef(t *testing.T) {
	pkgs, refs := spdxPackages(t, declaredNamed("free-text", &License{Name: "BSD-like, see LICENSE"}))

	got := pkgs["free-text"].Declared
	want := "LicenseRef-BSD-like-see-LICENSE"
	if got != want {
		t.Errorf("licenseDeclared = %q, want %q", got, want)
	}
	if strings.Contains(got, " ") {
		t.Errorf("licenseDeclared = %q contains a space, which no SPDX license expression may", got)
	}
	if name, ok := refs[want]; !ok || name != "BSD-like, see LICENSE" {
		t.Errorf("hasExtractedLicensingInfos[%q] name = %q (present=%v), want the original text", want, name, ok)
	}
}

// TestSPDXNameIsNotJoinedRawIntoAnExpression is the case the join makes worse
// than a single value: "MIT AND see LICENSE" parses as an expression right up to
// the operand that is not one, so a consumer either rejects the document or
// silently reads a license that does not exist.
func TestSPDXNameIsNotJoinedRawIntoAnExpression(t *testing.T) {
	pkgs, refs := spdxPackages(t, declaredNamed("mixed",
		&License{SpdxId: "MIT"},
		&License{Name: "see LICENSE"},
	))

	got := pkgs["mixed"].Declared
	if got == "MIT AND see LICENSE" {
		t.Fatalf("licenseDeclared = %q — a free-form name was joined in raw", got)
	}
	if want := "MIT AND LicenseRef-see-LICENSE"; got != want {
		t.Errorf("licenseDeclared = %q, want %q", got, want)
	}
	if _, ok := refs["LicenseRef-see-LICENSE"]; !ok {
		t.Errorf("LicenseRef-see-LICENSE is referenced but never defined; refs = %v", refs)
	}
}

// TestSPDXParenthesizesOnlyWhatItJoins covers both sides of the grouping rule:
// a joined expression keeps its operands together, and a value that ends up
// alone is not wrapped just because a sibling entry carried nothing.
func TestSPDXParenthesizesOnlyWhatItJoins(t *testing.T) {
	pkgs, _ := spdxPackages(t,
		declaredNamed("joined",
			&License{Expression: "MIT OR Apache-2.0"},
			&License{SpdxId: "AGPL-3.0-only"},
		),
		declaredNamed("alone",
			&License{Expression: "MIT OR Apache-2.0"},
			// Carries no value at all, so it renders nothing and must not
			// change how the entry that does render is grouped.
			&License{Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_DECLARED},
		),
	)

	if want := "(MIT OR Apache-2.0) AND AGPL-3.0-only"; pkgs["joined"].Declared != want {
		t.Errorf("joined licenseDeclared = %q, want %q — OR must not reassociate across the AND",
			pkgs["joined"].Declared, want)
	}
	if want := "MIT OR Apache-2.0"; pkgs["alone"].Declared != want {
		t.Errorf("alone licenseDeclared = %q, want %q — a dropped entry added parentheses",
			pkgs["alone"].Declared, want)
	}
}

// TestSPDXLegacyScalarPassesThroughUnchanged pins what the fix deliberately does
// not change. Producers set the scalar to whatever their package manager
// reported, and a large share of OS packages report something that is not an
// SPDX expression; re-encoding those here would rewrite what every existing
// document says. That migration is a decision, not a side effect, so the scalar
// path stays byte-for-byte as it was.
func TestSPDXLegacyScalarPassesThroughUnchanged(t *testing.T) {
	pkgs, _ := spdxPackages(t, &Package{
		Name: "scalar-free-text", Version: "1.0.0", Purl: "pkg:npm/scalar-free-text@1.0.0",
		License: "BSD-like, see LICENSE",
	})
	if got := pkgs["scalar-free-text"].Declared; got != "BSD-like, see LICENSE" {
		t.Errorf("licenseDeclared = %q, want the scalar verbatim", got)
	}
}

func TestSPDXLicenseRef(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"MIT", "LicenseRef-MIT"},
		{"BSD-like, see LICENSE", "LicenseRef-BSD-like-see-LICENSE"},
		{"see LICENSE", "LicenseRef-see-LICENSE"},
		{"GPL v2+", "LicenseRef-GPL-v2"},
		{"Apache 2.0", "LicenseRef-Apache-2.0"},
		// Nothing an identifier can be built from: SPDX has no way to reference
		// this, so the caller has to drop it rather than emit a bare prefix.
		{"?? ??", ""},
		{"", ""},
	} {
		if got := spdxLicenseRef(tc.name); got != tc.want {
			t.Errorf("spdxLicenseRef(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestSPDXUnreferenceableNameIsDropped: with no identifier to build, the entry
// cannot be referenced, and a document that names a license it never defines is
// invalid. NOASSERTION is the honest value.
func TestSPDXUnreferenceableNameIsDropped(t *testing.T) {
	pkgs, refs := spdxPackages(t, declaredNamed("unnameable", &License{Name: "?? ??"}))
	if got := pkgs["unnameable"].Declared; got != "NOASSERTION" {
		t.Errorf("licenseDeclared = %q, want NOASSERTION", got)
	}
	for id := range refs {
		if id == licenseRefPrefix || id == licenseRefPrefix+"-" {
			t.Errorf("emitted a bare LicenseRef prefix: %q", id)
		}
	}
}

// SPDX has no field for a conclusion's confidence or the file it was read from,
// and PackageLicenseComments is the one place the spec puts prose about how the
// license fields were arrived at. Free text, so this is for a human reading the
// document; the alternative was dropping the difference between a certainty and
// an inference entirely.
func TestSPDXRecordsWhatAConclusionWasBasedOn(t *testing.T) {
	var doc struct {
		Packages []struct {
			Name            string `json:"name"`
			LicenseComments string `json:"licenseComments"`
		} `json:"packages"`
	}
	require.NoError(t, json.Unmarshal([]byte(renderBom(t, FormatSpdxJSON, splitLicenseBom())), &doc))
	require.Len(t, doc.Packages, 1)

	got := doc.Packages[0].LicenseComments
	assert.Contains(t, got, "AGPL-3.0-only")
	assert.Contains(t, got, "node_modules/disagrees/LICENSE")
	assert.Contains(t, got, "0.98")
}

// A comment saying nothing is worse than none: a reader takes its presence as a
// sign there was something to say.
func TestSPDXLicenseCommentsAreEmptyWithNothingToSay(t *testing.T) {
	t.Run("nothing concluded", func(t *testing.T) {
		assert.Empty(t, spdxLicenseComments(nil))
	})

	t.Run("a conclusion carrying neither detail", func(t *testing.T) {
		assert.Empty(t, spdxLicenseComments([]*License{{
			SpdxId:      "MIT",
			Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED,
			Confidence:  1,
		}}))
	})

	// Full confidence says the same thing as no score attached, so it is not
	// worth a note on its own.
	t.Run("full confidence alone is not a note", func(t *testing.T) {
		assert.Empty(t, spdxLicenseComments([]*License{{
			SpdxId:      "MIT",
			Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED,
			Confidence:  1.0,
		}}))
	})

	t.Run("a location alone is", func(t *testing.T) {
		got := spdxLicenseComments([]*License{{
			SpdxId:      "MIT",
			Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED,
			Location:    "LICENSE",
			Confidence:  1,
		}})
		assert.Equal(t, "Concluded MIT: read from LICENSE.", got)
	})
}

// Both renderers apply the same rule to a conclusion's confidence, and the rule
// is that full confidence says nothing. The model documents 1.0 as what a value
// carries when it is a statement rather than a measurement, so a conclusion at
// 1.0 is asserting no measurement -- the same thing an entry with no score
// attached says. Reporting it would read as a score somebody took.
func TestFullConfidenceIsNotReportedByEitherRenderer(t *testing.T) {
	bom := &Sbom{
		Generator: &Generator{Vendor: "Mondoo, Inc", Name: "test", Version: "1"},
		Asset:     &Asset{Name: "test-asset", Platform: &Platform{Name: "linux", Version: "1"}},
		Packages: []*Package{{
			Name: "certain", Version: "1.0.0", Purl: "pkg:npm/certain@1.0.0",
			Licenses: []*License{{
				SpdxId:      "MIT",
				Acquisition: LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED,
				Confidence:  1.0,
				Location:    "LICENSE",
			}},
		}},
	}

	t.Run("cyclonedx omits the confidence property but keeps the location", func(t *testing.T) {
		c := cdxComponent(t, renderBom(t, FormatCycloneDxJSON, bom), "certain")
		require.Len(t, c.Licenses, 1)
		require.NotNil(t, c.Licenses[0].License)
		require.NotNil(t, c.Licenses[0].License.Properties)

		names := map[string]string{}
		for _, pr := range *c.Licenses[0].License.Properties {
			names[pr.Name] = pr.Value
		}
		assert.NotContains(t, names, "mondoo:license:confidence")
		assert.Equal(t, "LICENSE", names["mondoo:license:location"])
	})

	t.Run("spdx says the same", func(t *testing.T) {
		var doc struct {
			Packages []struct {
				LicenseComments string `json:"licenseComments"`
			} `json:"packages"`
		}
		require.NoError(t, json.Unmarshal([]byte(renderBom(t, FormatSpdxJSON, bom)), &doc))
		require.Len(t, doc.Packages, 1)
		assert.Equal(t, "Concluded MIT: read from LICENSE.", doc.Packages[0].LicenseComments)
		assert.NotContains(t, doc.Packages[0].LicenseComments, "confidence")
	})
}
