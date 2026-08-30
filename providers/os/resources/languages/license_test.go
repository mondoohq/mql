// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package languages_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func TestLicenseExpression(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []string
		want string
	}{
		// The overwhelmingly common case. A single license must not acquire
		// parentheses it did not have: "(MIT)" is a different string to every
		// consumer that compares identifiers, even though it parses the same.
		{"one license passes through", []string{"MIT"}, "MIT"},
		// A list means the package is offered under any of them and the consumer
		// chooses, which is what SPDX's OR says.
		{"a list is a choice", []string{"MIT", "Apache-2.0"}, "(MIT OR Apache-2.0)"},
		{"three", []string{"MIT", "Apache-2.0", "BSD-3-Clause"}, "(MIT OR Apache-2.0 OR BSD-3-Clause)"},
		// A manifest that declared nothing must report nothing, rather than an
		// empty or malformed expression that reads as a declaration.
		{"nil", nil, ""},
		{"empty", []string{}, ""},
		{"blank entries only", []string{"", "  "}, ""},
		// A blank among real entries must not become an empty OR operand, which
		// would not parse.
		{"blanks are dropped", []string{"MIT", "", "Apache-2.0"}, "(MIT OR Apache-2.0)"},
		{"one real entry among blanks", []string{"", "MIT", " "}, "MIT"},
		{"surrounding space is trimmed", []string{" MIT "}, "MIT"},
		// Passed through as the manifest wrote it: normalizing a name is the
		// consumer's decision, and rewriting here would discard what the file
		// actually said.
		{"non-SPDX text is not normalized", []string{"Apache License 2.0"}, "Apache License 2.0"},
		// Already an expression. Wrapping it keeps the result valid when it is
		// embedded in a larger one.
		{"an expression operand stays grouped", []string{"MIT", "GPL-2.0-only WITH Classpath-exception-2.0"},
			"(MIT OR GPL-2.0-only WITH Classpath-exception-2.0)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, languages.LicenseExpression(c.in))
		})
	}
}

// TestLicenseExpressionBounds covers the size bounds on registry-supplied
// license values. Every ecosystem feeding this function reads its input from a
// package index or an artifact, so the length of a license value is chosen by
// whoever published the package, and it flows on into SBOM documents, SARIF and
// generated NOTICE files unbounded.
//
// The caps are written as literals here rather than read from the package they
// bound: a test that took its expectation from the same constant as the
// implementation would move with it and pin nothing.
func TestLicenseExpressionBounds(t *testing.T) {
	// A license identifier of exactly n bytes.
	name := func(n int) string { return strings.Repeat("a", n) }

	// What a distribution actually pastes into a license field when it pastes
	// the terms instead of naming them.
	licenseText := "Permission is hereby granted, free of charge, to any person obtaining a copy " +
		"of this software and associated documentation files (the \"Software\"), to deal " +
		"in the Software without restriction, including without limitation the rights " +
		"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell " +
		"copies of the Software, and to permit persons to whom the Software is " +
		"furnished to do so, subject to the following conditions:"

	// An expression of exactly 1024 bytes: three operands at the per-operand
	// cap, one of 242, two parens and three " OR " separators.
	atExprCap := []string{name(256), name(256), name(256), name(242)}

	for _, c := range []struct {
		name string
		in   []string
		want string
	}{
		// --- the per-operand bound -----------------------------------------
		//
		// Real names are far shorter than the cap, and none of these may start
		// reporting "" because someone tightened it.
		{"a full SPDX license name is well under the cap",
			[]string{"GNU Free Documentation License v1.3 or later - no invariants - with cover texts"},
			"GNU Free Documentation License v1.3 or later - no invariants - with cover texts"},
		{"a real multi-license choice is well under the cap",
			[]string{"MPL-2.0", "GPL-2.0-or-later", "LGPL-2.1-or-later", "Apache-2.0", "MIT"},
			"(MPL-2.0 OR GPL-2.0-or-later OR LGPL-2.1-or-later OR Apache-2.0 OR MIT)"},
		{"an operand at the cap is kept", []string{name(256)}, name(256)},
		{"an operand one byte over the cap is dropped", []string{name(257)}, ""},
		// Dropped whole, never truncated: "Apache-2" is a different license to
		// every consumer comparing identifiers, not a shortened one.
		{"a pasted license text is dropped rather than truncated", []string{licenseText}, ""},
		// The oversized member is the only thing wrong with the list. A package
		// that names MIT and then pastes the terms still named MIT.
		{"an oversized operand does not take its siblings with it",
			[]string{"MIT", name(257), "Apache-2.0"}, "(MIT OR Apache-2.0)"},
		{"an oversized operand alone among blanks", []string{"", name(257), " "}, ""},

		// --- the total bound ------------------------------------------------
		//
		// Individually valid members join into an expression of any size: this
		// is what a `licenses` array with thousands of entries produces, and
		// the per-operand bound does not touch it.
		{"an expression one byte over the cap is dropped",
			[]string{name(256), name(256), name(256), name(243)}, ""},
		{"thousands of valid short members are not a license statement",
			repeated("MIT", 5000), ""},
		{"a long list of real identifiers past the cap is dropped",
			repeated("GPL-2.0-or-later", 100), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, languages.LicenseExpression(c.in))
		})
	}

	// Checked apart from the table because the assertion is on the length: it
	// is the byte before the cliff, and it must survive.
	t.Run("an expression at the cap is kept", func(t *testing.T) {
		got := languages.LicenseExpression(atExprCap)
		require.NotEmpty(t, got, "an expression exactly at the cap must not be dropped")
		assert.Equal(t, 1024, len(got))
		assert.Equal(t, "("+strings.Join(atExprCap, " OR ")+")", got)
	})
}

func repeated(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}
