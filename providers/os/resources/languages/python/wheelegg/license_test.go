// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wheelegg

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// license reads one METADATA document end to end, so every case below exercises
// the real parser rather than the helper underneath it.
func license(t *testing.T, content string) string {
	t.Helper()
	pkg, err := ParseMIME(strings.NewReader(content), "METADATA")
	require.NoError(t, err)
	return pkg.License
}

// The case that motivated this: a wheel built by a current toolchain. PEP 639
// deprecates `License` in favour of `License-Expression` and forbids carrying
// both, so this document is the whole of what such a distribution says — and it
// previously reported no license at all.
func TestLicenseExpressionIsRead(t *testing.T) {
	assert.Equal(t, "Apache-2.0", license(t, `Metadata-Version: 2.4
Name: attrs
Version: 25.1.0
License-Expression: Apache-2.0
`))
}

func TestLicenseExpressionKeepsItsOperators(t *testing.T) {
	assert.Equal(t, "MIT OR Apache-2.0", license(t, `Metadata-Version: 2.4
Name: dual
Version: 1.0
License-Expression: MIT OR Apache-2.0
`))
}

// Precedence, tier by tier. Each is only consulted when the one above it said
// nothing, so a document carrying several must answer with the most precise.
func TestExpressionBeatsFreeTextAndClassifiers(t *testing.T) {
	assert.Equal(t, "Apache-2.0", license(t, `Metadata-Version: 2.4
Name: mixed
Version: 1.0
License-Expression: Apache-2.0
License: Apache Software License, Version 2.0
Classifier: License :: OSI Approved :: Apache Software License
`))
}

func TestFreeTextBeatsClassifiers(t *testing.T) {
	assert.Equal(t, "MIT", license(t, `Metadata-Version: 2.1
Name: pyftpdlib
Version: 1.5.7
License: MIT
Classifier: License :: OSI Approved :: MIT License
`))
}

func TestClassifierAnswersWhenNothingElseDoes(t *testing.T) {
	assert.Equal(t, "BSD License", license(t, `Metadata-Version: 2.1
Name: classified
Version: 1.0
Classifier: Development Status :: 5 - Production/Stable
Classifier: License :: OSI Approved :: BSD License
Classifier: Programming Language :: Python
`))
}

// Several license classifiers are a choice among them — dual licensing, as this
// vocabulary spells it — so they are OR-joined and parenthesised.
func TestSeveralClassifiersAreAChoice(t *testing.T) {
	assert.Equal(t, "(MIT License OR Apache Software License)", license(t, `Metadata-Version: 2.1
Name: dual
Version: 1.0
Classifier: License :: OSI Approved :: MIT License
Classifier: License :: OSI Approved :: Apache Software License
`))
}

// The same license under two spellings is not a choice, and must not be
// rendered as one.
func TestRepeatedClassifierIsNotAChoice(t *testing.T) {
	assert.Equal(t, "MIT License", license(t, `Metadata-Version: 2.1
Name: repeated
Version: 1.0
Classifier: License :: OSI Approved :: MIT License
Classifier: License :: OSI Approved :: mit license
`))
}

// Classifiers that name no specific license state nothing, and reporting one as
// the license would assert a licensing fact the distribution did not make.
func TestClassifiersNamingNoLicenseAreNotALicense(t *testing.T) {
	for _, c := range []string{
		"License :: OSI Approved",
		"License :: Public Domain",
		"License :: Freeware",
		"License :: Other/Proprietary License",
		"License :: DFSG approved",
	} {
		assert.Equal(t, "", license(t, `Metadata-Version: 2.1
Name: vague
Version: 1.0
Classifier: `+c+`
`), c)
	}
}

// A non-license classifier must never be mistaken for one, however it is
// punctuated.
func TestNonLicenseClassifiersAreIgnored(t *testing.T) {
	assert.Equal(t, "", license(t, `Metadata-Version: 2.1
Name: unlicensed
Version: 1.0
Classifier: Development Status :: 5 - Production/Stable
Classifier: Topic :: Software Development :: Libraries :: Python Modules
Classifier: Framework :: Django :: 4.2
`))
}

// A distribution that states nothing gets "", not something that reads as a
// declaration.
func TestNoLicenseStatedIsEmpty(t *testing.T) {
	assert.Equal(t, "", license(t, `Metadata-Version: 2.1
Name: bare
Version: 1.0
Summary: says nothing about licensing
`))
}

// A pasted license TEXT is not a license NAME. Historically the free-text
// field had no length limit and distributions put a whole license in it,
// continuation line by continuation line; textproto folds that into one value.
// Carried through it would reach every SBOM as an identifier no consumer can
// match.
func TestPastedLicenseTextIsNotReportedAsAName(t *testing.T) {
	body := strings.Repeat("Redistribution and use in source and binary forms are permitted. ", 20)
	require.Greater(t, len(body), licenseValueMaxBytes)

	assert.Equal(t, "", license(t, `Metadata-Version: 2.1
Name: verbose
Version: 1.0
License: `+body+`
`))
}

// ...and when that happens, the classifier below it answers instead. This is
// the case the length bound exists to reach.
func TestPastedTextFallsThroughToTheClassifier(t *testing.T) {
	body := strings.Repeat("BSD-3-Clause, full text follows. ", 20)
	require.Greater(t, len(body), licenseValueMaxBytes)

	assert.Equal(t, "BSD License", license(t, `Metadata-Version: 2.1
Name: verbose
Version: 1.0
License: `+body+`
Classifier: License :: OSI Approved :: BSD License
`))
}

// An oversized expression is bounded for the same reason: being well-formed
// SPDX supplies no length limit, since "MIT OR MIT OR ..." is valid at any
// size, and metadata arrives from a package index rather than from the
// repository being scanned.
func TestOversizedExpressionIsDropped(t *testing.T) {
	huge := "MIT" + strings.Repeat(" OR MIT", 100)
	require.Greater(t, len(huge), licenseValueMaxBytes)

	assert.Equal(t, "", license(t, `Metadata-Version: 2.4
Name: huge
Version: 1.0
License-Expression: `+huge+`
`))
}

// The header block ends at the first blank line. A README that discusses
// licensing is the message body and must not be read as a declaration — which
// textproto gives us, and this pins so a future reader cannot regress it.
func TestBodyIsNotReadAsMetadata(t *testing.T) {
	assert.Equal(t, "", license(t, `Metadata-Version: 2.1
Name: readme
Version: 1.0

License: GPL-3.0-only
Classifier: License :: OSI Approved :: MIT License
`))
}
