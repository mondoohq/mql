// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifestmf

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManifestLicense is the regression test for Bundle-License being parsed
// into Headers and then never reported: a bundle naming its license reported
// none.
//
// Every input below is the shape of a real manifest — they were taken from a
// sample of MANIFEST.MF files on GitHub, which is also where the frequencies
// cited in the comments come from.
func TestManifestLicense(t *testing.T) {
	for _, c := range []struct {
		name   string
		header string
		want   string
	}{
		{
			// The canonical form: an identifier plus a link to its text.
			name:   "identifier with a link",
			header: `Bundle-License: Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"`,
			want:   "Apache-2.0",
		},
		{
			// Not SPDX, but it is what the bundle said, and normalizing it is
			// a consumer's decision.
			name:   "bare identifier",
			header: "Bundle-License: Apache 2.0",
			want:   "Apache 2.0",
		},
		{
			name:   "identifier with a link, no quotes",
			header: "Bundle-License: EPL-2.0;link=https://www.eclipse.org/legal/epl-2.0",
			want:   "EPL-2.0",
		},
		{
			// The grammar makes ',' a separator, but Eclipse/Tycho bundles
			// write an identifier that contains one. OR-joining this would
			// report the bundle as offered under "The Apache License" or
			// "Version 2.0" — a choice it never offered.
			name:   "identifier containing a comma",
			header: `Bundle-License: The Apache License, Version 2.0;link="http://www.apache.org/licenses/LICENSE-2.0.txt"`,
			want:   "The Apache License, Version 2.0",
		},
		{
			name:   "identifier with a version suffix",
			header: `Bundle-License: Eclipse Public License v2.0;link="http://www.eclipse.org/legal/epl-2.0"`,
			want:   "Eclipse Public License v2.0",
		},
		{
			// A quoted attribute value carries both separators, so splitting
			// must not see them.
			name:   "comma inside a quoted description",
			header: `Bundle-License: Apache-2.0;description="Apache License, Version 2.0";link="https://www.apache.org/licenses/LICENSE-2.0"`,
			want:   "Apache-2.0",
		},
		{
			// Two licenses, both stated as identifiers. Every piece is
			// identifier-shaped, so the comma really is the separator the
			// grammar says it is and the bundle is offering a choice.
			name:   "two identifiers",
			header: `Bundle-License: MIT;link="https://opensource.org/licenses/MIT",Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"`,
			want:   "(MIT OR Apache-2.0)",
		},
		{
			// The most common real header by a wide margin, and the reason
			// this fix leaves most bundles reporting nothing. A link to the
			// terms is not the identity of the terms: a URL in a field
			// consumers compare against "Apache-2.0" matches nothing while
			// reading as a stated identifier.
			name:   "url only",
			header: "Bundle-License: https://www.apache.org/licenses/LICENSE-2.0.txt",
			want:   "",
		},
		{
			// A genuine dual license, stated as two URLs. Nothing nameable.
			name:   "two urls",
			header: "Bundle-License: https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.txt, https://www.gnu.org/software/classpath/license.html",
			want:   "",
		},
		{
			// The description names the license where the identifier is a URL,
			// but it is prose — bnd's own example is a whole sentence — so it
			// is not promoted to an identifier.
			name:   "url identifier with a describing attribute",
			header: "Bundle-License: https://opensource.org/licenses/BSD-2-Clause;description=BSD 2-Clause License",
			want:   "",
		},
		{
			// The magic value states that the license is *not* here.
			name:   "external",
			header: "Bundle-License: <<EXTERNAL>>",
			want:   "",
		},
		{
			name:   "no Bundle-License header",
			header: "Bundle-Name: Example",
			want:   "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			mf := "Manifest-Version: 1.0\nBundle-SymbolicName: com.example\nBundle-Version: 1.0.0\n" + c.header + "\n"
			info, err := (&Extractor{}).Parse(strings.NewReader(mf), "META-INF/MANIFEST.MF")
			require.NoError(t, err)

			root := info.Root()
			require.NotNil(t, root)
			assert.Equal(t, c.want, root.License)
		})
	}
}

// TestManifestLicenseContinuationLine covers a Bundle-License wrapped across
// source lines, which is how a manifest carrying a link is normally written —
// the header limit is 72 bytes, so the real ones are nearly always wrapped.
func TestManifestLicenseContinuationLine(t *testing.T) {
	mf := "Manifest-Version: 1.0\n" +
		"Bundle-SymbolicName: com.example\n" +
		"Bundle-License: The Apache License, Version 2.0;link=\"http://www.apache.\n" +
		" org/licenses/LICENSE-2.0.txt\"\n"

	info, err := (&Extractor{}).Parse(strings.NewReader(mf), "META-INF/MANIFEST.MF")
	require.NoError(t, err)

	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "The Apache License, Version 2.0", root.License)
}

// TestManifestLicenseFixtures pins the checked-in fixtures. The OSGi one states
// its license as a URL, so it reports none — the same as before this fix, and
// deliberately: it must not start emitting the URL as an identifier.
func TestManifestLicenseFixtures(t *testing.T) {
	for _, c := range []struct{ fixture, want string }{
		{"./testdata/osgi.MANIFEST.MF", ""},
		{"./testdata/simple.MANIFEST.MF", ""},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			f, err := os.Open(c.fixture)
			require.NoError(t, err)
			defer f.Close()

			info, err := (&Extractor{}).Parse(f, "META-INF/MANIFEST.MF")
			require.NoError(t, err)
			assert.Equal(t, c.want, info.Root().License)
		})
	}
}

// TestManifestLicenseBounds covers the size bounds on Bundle-License. A
// MANIFEST.MF is read out of a JAR someone else built, and nothing in the OSGi
// grammar bounds a license-identifier — the value flows into SBOM documents and
// generated NOTICE files exactly as the artifact wrote it.
//
// The caps are literals here rather than the constants the implementation
// reads: an expectation taken from the same constant would move with it and pin
// nothing.
func TestManifestLicenseBounds(t *testing.T) {
	// A license identifier of exactly n bytes. It carries no ',' or ';', so the
	// header parses as one entry.
	name := func(n int) string { return strings.Repeat("a", n) }

	for _, c := range []struct {
		name   string
		header string
		want   string
	}{
		// A real identifier is nowhere near the cap, and must not start
		// reporting "" because someone tightened it.
		{
			name:   "a real identifier is well under the cap",
			header: "Bundle-License: GNU Lesser General Public License, Version 2.1;link=\"https://www.gnu.org/licenses/lgpl-2.1.html\"",
			want:   "GNU Lesser General Public License, Version 2.1",
		},
		{
			name:   "an identifier at the cap is kept",
			header: "Bundle-License: " + name(256),
			want:   name(256),
		},
		{
			name:   "an identifier one byte over the cap is dropped",
			header: "Bundle-License: " + name(257),
			want:   "",
		},
		{
			// Dropped whole, never truncated: a cut-off identifier reads as a
			// different license rather than a shortened one.
			name:   "a pasted license text is dropped rather than truncated",
			header: "Bundle-License: " + strings.Repeat("Permission is hereby granted free of charge to any person ", 10),
			want:   "",
		},
		{
			// The oversized entry is the only thing wrong with the header.
			name:   "an oversized identifier does not take its siblings with it",
			header: "Bundle-License: " + name(300) + ",MIT",
			want:   "MIT",
		},
		{
			// Individually valid identifiers rejoin into a value of any size.
			// ", " is not SPDX's OR, but it is carried into the same field, so
			// it takes the same total bound.
			name:   "many valid identifiers past the total cap are dropped",
			header: "Bundle-License: " + strings.Repeat("Apache-2.0,", 200) + "MIT",
			want:   "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			mf := "Manifest-Version: 1.0\nBundle-SymbolicName: com.example\nBundle-Version: 1.0.0\n" + c.header + "\n"
			info, err := (&Extractor{}).Parse(strings.NewReader(mf), "META-INF/MANIFEST.MF")
			require.NoError(t, err)

			root := info.Root()
			require.NotNil(t, root)
			assert.Equal(t, c.want, root.License)
		})
	}
}

// A URL is a link to the terms, not the identity of the terms, and a scheme is
// not what makes it one. Reporting a schemeless URL as a license identifier is
// the outcome dropping the schemeful form exists to avoid.
func TestBundleLicenseDropsSchemelessURLs(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"https://www.eclipse.org/legal/epl-2.0/", ""},
		{"http://www.apache.org/licenses/LICENSE-2.0.txt", ""},
		{"www.apache.org/licenses/LICENSE-2.0", ""},
		{"eclipse.org/legal/epl-2.0/", ""},
		// Still a license name, not a link: no dotted host followed by a path.
		{"Apache-2.0", "Apache-2.0"},
		{"MIT", "MIT"},
		{"GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"The Apache License, Version 2.0", "The Apache License, Version 2.0"},
		// A name beside a link keeps the name and drops the link.
		{"Apache-2.0, www.apache.org/licenses/LICENSE-2.0", "Apache-2.0"},
	} {
		m := &manifest{Headers: map[string]string{headerBundleLicense: tc.header}}
		assert.Equal(t, tc.want, m.license(), "Bundle-License: %s", tc.header)
	}
}

// OSGi's grammar makes ',' a separator between licenses, but manifests also
// write a name that contains one. Which it is, is decided by what the pieces
// look like: all identifier-shaped means the comma separated two licenses, and
// the bundle is offering a choice, which is SPDX's OR. Anything else is treated
// as one name that happens to contain a comma.
//
// The asymmetry is deliberate. Rejoining a genuine list loses only the OR;
// OR-joining a split name would report a bundle as dual-licensed under terms it
// never offered, so anything not clearly a list is rejoined.
func TestBundleLicenseTellsAListFromANameWithAComma(t *testing.T) {
	for _, tc := range []struct{ name, header, want string }{
		{
			"a list of identifiers is a choice",
			"MIT,Apache-2.0",
			"(MIT OR Apache-2.0)",
		},
		{
			"three of them",
			"MIT, Apache-2.0, BSD-3-Clause",
			"(MIT OR Apache-2.0 OR BSD-3-Clause)",
		},
		{
			// The Eclipse/Tycho shape: one license whose name carries a comma.
			"a name containing a comma is one license",
			"The Apache License, Version 2.0",
			"The Apache License, Version 2.0",
		},
		{
			// Not clearly a list, so left alone rather than guessed at.
			"a piece that is not an identifier keeps the whole thing joined",
			"MIT, GPL-2.0-only WITH Classpath-exception-2.0",
			"MIT, GPL-2.0-only WITH Classpath-exception-2.0",
		},
		{
			"a single identifier is unchanged",
			"Apache-2.0",
			"Apache-2.0",
		},
		{
			"a single name is unchanged",
			"Eclipse Public License v2.0",
			"Eclipse Public License v2.0",
		},
		{
			// A link beside a name leaves one entry, so there is no list to
			// join and no parentheses to add.
			"a dropped link leaves a single license alone",
			"Apache-2.0, www.apache.org/licenses/LICENSE-2.0",
			"Apache-2.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &manifest{Headers: map[string]string{headerBundleLicense: tc.header}}
			assert.Equal(t, tc.want, m.license())
		})
	}
}
