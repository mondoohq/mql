// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeclaredLicensePlacesTheRightField(t *testing.T) {
	for _, tc := range []struct {
		name       string
		value      string
		spdxID     string
		expression string
		licName    string
	}{
		{name: "a bare identifier", value: "MIT", spdxID: "MIT"},
		{name: "an identifier with punctuation", value: "GPL-2.0-or-later", spdxID: "GPL-2.0-or-later"},
		{name: "an identifier with a plus", value: "Apache-2.0+", spdxID: "Apache-2.0+"},
		// Not on the SPDX list, but identifier-shaped. Rendering it as an id is
		// right: this package must not drop a license it cannot recognise, and a
		// consumer validating against the list says something more useful than a
		// producer that silently downgraded it.
		{name: "an unlisted identifier", value: "OurInternalTerms-1.0", spdxID: "OurInternalTerms-1.0"},
		{name: "an OR expression", value: "MIT OR Apache-2.0", expression: "MIT OR Apache-2.0"},
		{name: "an AND expression", value: "MIT AND BSD-3-Clause", expression: "MIT AND BSD-3-Clause"},
		{name: "a WITH exception", value: "GPL-2.0-only WITH Classpath-exception-2.0", expression: "GPL-2.0-only WITH Classpath-exception-2.0"},
		{name: "a parenthesised expression", value: "(MIT OR Apache-2.0)", expression: "(MIT OR Apache-2.0)"},
		{name: "free text", value: "see the LICENSE file", licName: "see the LICENSE file"},
		// Identifier-SHAPED but not on the SPDX list. It still goes in the id
		// field: this package deliberately does not validate against the list,
		// so that an unlisted identifier reaches the document and a consumer
		// that does validate can say so.
		{name: "an identifier-shaped unlisted name", value: "BSD-like", spdxID: "BSD-like"},
		{name: "free text naming a license", value: "BSD style, see COPYING", licName: "BSD style, see COPYING"},
		// "and" is not an operator: SPDX keywords are case-sensitive, and
		// several published license names contain the lowercase word.
		{name: "a name containing the word and", value: "Sleepycat and others", licName: "Sleepycat and others"},
		{name: "a name containing the word or", value: "Artistic or GPL", licName: "Artistic or GPL"},
		// Parentheses alone do not make an expression. Emitting this as one
		// produces a document no consumer can parse.
		{name: "free text with parentheses", value: "BSD (see LICENSE)", licName: "BSD (see LICENSE)"},
		{name: "a note in parentheses", value: "MIT (with a local amendment)", licName: "MIT (with a local amendment)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := DeclaredLicense(tc.value)
			require.NotNil(t, l)
			assert.Equal(t, tc.spdxID, l.GetSpdxId(), "spdx_id")
			assert.Equal(t, tc.expression, l.GetExpression(), "expression")
			assert.Equal(t, tc.licName, l.GetName(), "name")

			// Exactly one of the three, always. A document setting two is
			// rejected by CycloneDX.
			set := 0
			for _, v := range []string{l.GetSpdxId(), l.GetExpression(), l.GetName()} {
				if v != "" {
					set++
				}
			}
			assert.Equal(t, 1, set, "exactly one value field must be set")
		})
	}
}

// A declaration is a statement the package made about itself, not a measurement
// somebody took of it, so it is recorded as certain and as declared.
func TestDeclaredLicenseIsCertainAndDeclared(t *testing.T) {
	l := DeclaredLicense("MIT")
	require.NotNil(t, l)
	assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_DECLARED, l.GetAcquisition())
	assert.Equal(t, 1.0, l.GetConfidence())
}

// Nothing to record is recorded as nothing. An entry naming no license asserts
// a licensing fact the producer does not have.
func TestNoLicenseYieldsNoEntry(t *testing.T) {
	for _, v := range []string{"", "   ", "\t\n"} {
		assert.Nil(t, DeclaredLicense(v), "%q", v)
		assert.Nil(t, DeclaredLicenses(v), "%q", v)
	}
}

// Grouping carries meaning -- AND binds tighter than OR -- so an expression is
// stored exactly as written rather than normalised.
func TestExpressionGroupingSurvives(t *testing.T) {
	const grouped = "(MIT OR Apache-2.0) AND BSD-3-Clause"
	l := DeclaredLicense(grouped)
	require.NotNil(t, l)
	assert.Equal(t, grouped, l.GetExpression())
}

func TestDeclaredLicensesWrapsASingleEntry(t *testing.T) {
	got := DeclaredLicenses("MIT")
	require.Len(t, got, 1)
	assert.Equal(t, "MIT", got[0].GetSpdxId())
}

// A conclusion is a measurement rather than a statement, so unlike a declared
// license it carries where it was read from and how sure whoever read it was.
func TestConcludedLicense(t *testing.T) {
	t.Run("value handling is shared with declared", func(t *testing.T) {
		assert.Equal(t, "MIT", ConcludedLicense("MIT", "", 1).GetSpdxId())
		assert.Equal(t, "MIT OR Apache-2.0", ConcludedLicense("MIT OR Apache-2.0", "", 1).GetExpression())
		assert.Equal(t, "BSD-like, see LICENSE", ConcludedLicense("BSD-like, see LICENSE", "", 1).GetName())
	})

	t.Run("acquisition and location are what differ", func(t *testing.T) {
		l := ConcludedLicense("AGPL-3.0-only", " node_modules/x/LICENSE ", 0.98)
		require.NotNil(t, l)
		assert.Equal(t, LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED, l.GetAcquisition())
		assert.Equal(t, "node_modules/x/LICENSE", l.GetLocation())
		assert.Equal(t, 0.98, l.GetConfidence())
	})

	// A score above 1 is a producer bug rather than extra certainty, so it
	// clamps to the top of the range instead of travelling as written, where a
	// consumer ranking conclusions would read it as a real measurement.
	t.Run("a score above 1 clamps to 1", func(t *testing.T) {
		for _, in := range []float64{1.5, 42} {
			assert.Equal(t, 1.0, ConcludedLicense("MIT", "", in).GetConfidence(), "confidence %v", in)
		}
		assert.Equal(t, 1.0, ConcludedLicense("MIT", "", 1).GetConfidence())
	})

	// The case that matters, and the one that used to read as certainty: no
	// score is not a perfect score. An importer whose format carries no
	// confidence passes 0, and promoting that to 1.0 would put a conclusion
	// nobody measured alongside one that matched exactly -- which is the
	// distinction the field exists to preserve.
	t.Run("no score stays no score", func(t *testing.T) {
		for _, in := range []float64{0, -1, -0.5} {
			assert.Equal(t, 0.0, ConcludedLicense("MIT", "", in).GetConfidence(), "confidence %v", in)
		}
	})

	// An entry naming no license asserts a fact the producer does not have.
	t.Run("no value means no entry", func(t *testing.T) {
		assert.Nil(t, ConcludedLicense("", "somewhere", 1))
		assert.Nil(t, ConcludedLicense("   ", "somewhere", 1))
	})
}
