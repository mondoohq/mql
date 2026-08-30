// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package languages_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
