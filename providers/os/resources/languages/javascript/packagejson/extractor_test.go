// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagejson

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers/os/resources/languages"
	"go.mondoo.com/mql/v13/sbom"
)

func TestPackageJsonExtractor(t *testing.T) {
	f, err := os.Open("./testdata/express-package.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/package.json")
	assert.Nil(t, err)

	root := info.Root()

	assert.Equal(t, &languages.Package{
		Name:         "express",
		Version:      "4.16.4",
		Description:  "Fast, unopinionated, minimalist web framework",
		Author:       "TJ Holowaychuk",
		License:      "MIT",
		Purl:         "pkg:npm/express@4.16.4",
		Cpes:         []string{"cpe:2.3:a:express:express:4.16.4:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/package.json"}},
	}, root, "express package is not as expected")

	list := info.Transitive()
	assert.Equal(t, 31, len(list))

	// ensure the package is in the list — Find returns the root entry,
	// which carries the package.json description/author/license.
	p := list.Find("express")
	assert.Equal(t, &languages.Package{
		Name:         "express",
		Version:      "4.16.4",
		Description:  "Fast, unopinionated, minimalist web framework",
		Author:       "TJ Holowaychuk",
		License:      "MIT",
		Purl:         "pkg:npm/express@4.16.4",
		Cpes:         []string{"cpe:2.3:a:express:express:4.16.4:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/package.json"}},
	}, p, "express package is not as expected")

	p = list.Find("path-to-regexp")
	assert.Equal(t, &languages.Package{
		Name:         "path-to-regexp",
		Version:      "0.1.7",
		Purl:         "pkg:npm/path-to-regexp@0.1.7",
		Cpes:         []string{"cpe:2.3:a:path-to-regexp:path-to-regexp:0.1.7:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/package.json"}},
	}, p, "path-to-regexp package is not as expected")

	p = list.Find("range-parser")
	assert.Equal(t, &languages.Package{
		Name:         "range-parser",
		Version:      "~1.2.0",
		Purl:         "pkg:npm/range-parser@1.2.0",
		Cpes:         []string{"cpe:2.3:a:range-parser:range-parser:1.2.0:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/package.json"}},
	}, p, "range-parser package is not as expected")
}

func TestPackageJsonExtractorAuthorForms(t *testing.T) {
	// package.json supports two `author` shapes — string ("Name <email>")
	// and object ({"name":..., "email":..., "url":...}). Both must
	// surface as the bare name on languages.Package.Author.
	cases := []struct {
		name     string
		raw      string
		wantName string
	}{
		{
			name:     "string with email and url",
			raw:      `{"name":"x","version":"1","author":"Jane Doe <jane@example.com> (https://example.com)"}`,
			wantName: "Jane Doe",
		},
		{
			name:     "string with name only",
			raw:      `{"name":"x","version":"1","author":"Jane Doe"}`,
			wantName: "Jane Doe",
		},
		{
			name:     "object form",
			raw:      `{"name":"x","version":"1","author":{"name":"Jane Doe","email":"jane@example.com"}}`,
			wantName: "Jane Doe",
		},
		{
			name:     "missing author",
			raw:      `{"name":"x","version":"1"}`,
			wantName: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := (&Extractor{}).Parse(strings.NewReader(tc.raw), "p/package.json")
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, info.Root().Author)
		})
	}
}

// TestPackageJsonLicenseForms is the regression test for the deprecated
// `licenses` array being ignored: `licenseExpression` read only `license`, so a
// package published before npm settled on that field reported no license at
// all. npm deprecated the array in 2014, but the registry does not rewrite what
// was already published, and those packages are still installed today.
//
// The testdata fixtures for both deprecated shapes were already checked in —
// only the parser never read them.
func TestPackageJsonLicenseForms(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "current license string",
			raw:  `{"name":"x","version":"1","license":"MIT"}`,
			want: "MIT",
		},
		{
			// An SPDX expression is one string and must survive intact.
			name: "license string carrying an expression",
			raw:  `{"name":"x","version":"1","license":"(MIT OR Apache-2.0)"}`,
			want: "(MIT OR Apache-2.0)",
		},
		{
			// The deprecated object form of `license`.
			name: "license object",
			raw:  `{"name":"x","version":"1","license":{"type":"ISC","url":"https://opensource.org/licenses/ISC"}}`,
			want: "ISC",
		},
		{
			// The form this fix is about, and the one that read empty before.
			name: "deprecated licenses array",
			raw: `{"name":"x","version":"1","licenses":[` +
				`{"type":"MIT","url":"https://www.opensource.org/licenses/mit-license.php"},` +
				`{"type":"Apache-2.0","url":"https://opensource.org/licenses/apache2.0.php"}]}`,
			want: "(MIT OR Apache-2.0)",
		},
		{
			// A one-member array must not acquire parentheses: "(MIT)" is a
			// different string to every consumer comparing identifiers.
			name: "licenses array with one member",
			raw:  `{"name":"x","version":"1","licenses":[{"type":"MIT","url":"https://example.com"}]}`,
			want: "MIT",
		},
		{
			// Some packages wrote the array members as bare strings.
			name: "licenses array of strings",
			raw:  `{"name":"x","version":"1","licenses":["MIT","Apache-2.0"]}`,
			want: "(MIT OR Apache-2.0)",
		},
		{
			// `license` is the field npm kept; the array is the legacy fallback.
			name: "license wins over licenses",
			raw:  `{"name":"x","version":"1","license":"MIT","licenses":[{"type":"Apache-2.0"}]}`,
			want: "MIT",
		},
		{
			// A `license` that names nothing is not a statement, so the legacy
			// array is still read.
			name: "license naming nothing falls through to licenses",
			raw:  `{"name":"x","version":"1","license":{"url":"https://example.com"},"licenses":[{"type":"MIT"}]}`,
			want: "MIT",
		},
		{
			// A link to the terms is not the identity of the terms. Reporting
			// the URL in a field consumers read as an identifier is worse than
			// reporting nothing.
			name: "a url alone is not a license",
			raw:  `{"name":"x","version":"1","licenses":[{"url":"https://opensource.org/licenses/ISC"}]}`,
			want: "",
		},
		{
			name: "no license stated",
			raw:  `{"name":"x","version":"1"}`,
			want: "",
		},
		{
			name: "empty license string",
			raw:  `{"name":"x","version":"1","license":""}`,
			want: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			info, err := (&Extractor{}).Parse(strings.NewReader(c.raw), "p/package.json")
			require.NoError(t, err)
			assert.Equal(t, c.want, info.Root().License)
		})
	}
}

// TestPackageJsonLicenseFixtures runs the same fix against the checked-in
// fixtures for the two deprecated shapes, which reported "" before.
func TestPackageJsonLicenseFixtures(t *testing.T) {
	for _, c := range []struct{ fixture, want string }{
		{"./testdata/license_spdx.json", "BSD-3-Clause"},
		{"./testdata/license_spdx_expression.json", "(MIT OR Apache-2.0)"},
		{"./testdata/license_deprecated_01.json", "ISC"},
		{"./testdata/license_deprecated_02.json", "(MIT OR Apache-2.0)"},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			f, err := os.Open(c.fixture)
			require.NoError(t, err)
			defer f.Close()

			info, err := (&Extractor{}).Parse(f, "p/package.json")
			require.NoError(t, err)
			assert.Equal(t, c.want, info.Root().License)
		})
	}
}

// TestPackageJsonLicenseBounds covers the size bounds on package.json's license
// fields. The deprecated `licenses` array is the worst case in any ecosystem
// here: it is a JSON array of registry-supplied strings with no bound of its
// own, and what it produces flows into SBOM documents, SARIF and generated
// NOTICE files.
//
// The cap is a literal here rather than the constant the implementation reads:
// an expectation taken from the same constant would move with it and pin
// nothing.
func TestPackageJsonLicenseBounds(t *testing.T) {
	// A license identifier of exactly n bytes, carrying nothing that needs JSON
	// escaping.
	name := func(n int) string { return strings.Repeat("a", n) }

	// 500 members, each individually a valid identifier.
	many := make([]string, 500)
	for i := range many {
		many[i] = `{"type":"MIT"}`
	}

	for _, c := range []struct {
		name string
		raw  string
		want string
	}{
		{
			// A real name is nowhere near the cap and must keep being reported.
			name: "a full license name is well under the cap",
			raw:  `{"name":"x","version":"1","license":"GNU Lesser General Public License, Version 2.1"}`,
			want: "GNU Lesser General Public License, Version 2.1",
		},
		{
			name: "an oversized license string is dropped",
			raw:  `{"name":"x","version":"1","license":"` + name(300) + `"}`,
			want: "",
		},
		{
			// An oversized `license` names nothing usable, so the legacy array
			// is still consulted — the same fallthrough as a `license` that
			// carries only a url.
			name: "an oversized license falls through to the legacy array",
			raw:  `{"name":"x","version":"1","license":"` + name(300) + `","licenses":[{"type":"MIT"}]}`,
			want: "MIT",
		},
		{
			// The oversized member is the only thing wrong with the array.
			name: "an oversized member does not take its siblings with it",
			raw:  `{"name":"x","version":"1","licenses":[{"type":"` + name(300) + `"},{"type":"MIT"}]}`,
			want: "MIT",
		},
		{
			name: "an array past the total cap is dropped",
			raw:  `{"name":"x","version":"1","licenses":[` + strings.Join(many, ",") + `]}`,
			want: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			info, err := (&Extractor{}).Parse(strings.NewReader(c.raw), "p/package.json")
			require.NoError(t, err)
			assert.Equal(t, c.want, info.Root().License)
		})
	}
}
