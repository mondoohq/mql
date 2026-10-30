// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A resource inside a `/* ... */` comment is not deployed, so it must not be
// reported. Before block comments were lexed, the tokenizer saw the commented
// body as ordinary source and emitted a phantom resource, which made a policy
// fail on infrastructure that does not exist.
func TestParseBicepIgnoresCommentedOutResource(t *testing.T) {
	src := `param a string

/*
resource commented 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'ghost'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
*/

resource real 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'real'
}
`
	parsed := parseBicep(src)

	require.Len(t, parsed.resources, 1, "only the uncommented resource should be reported")
	assert.Equal(t, "real", parsed.resources[0].symbolicName)
	assert.Equal(t, "'real'", parsed.resources[0].name)
	require.Len(t, parsed.parameters, 1)
	assert.Equal(t, "a", parsed.parameters[0].name)
}

// An unbalanced delimiter inside a block comment must not consume the rest of
// the file. The depth counter is only fooled when the comment body is treated
// as source, so this pins the string-aware blanking.
func TestParseBicepUnbalancedDelimiterInBlockComment(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"open brace", "/* TODO: reinstate the { block below */\n"},
		{"open paren", "/* see foo( for details */\n"},
		{"open bracket", "/* the [ here is prose */\n"},
		{"odd quote", "/* don't let this quote leak */\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.src + `resource real 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'real'
}
param p string
`
			parsed := parseBicep(src)

			require.Len(t, parsed.resources, 1, "the comment must not swallow the file")
			assert.Equal(t, "real", parsed.resources[0].symbolicName)
			require.Len(t, parsed.parameters, 1)
			assert.Equal(t, "p", parsed.parameters[0].name)
		})
	}
}

// A `/*` sequence inside a string literal is not a comment opener. Blanking it
// would corrupt the value, so the stripper has to share the lexer's string
// rules rather than doing a plain text scan.
func TestStripBlockCommentsIgnoresCommentMarkersInStrings(t *testing.T) {
	src := `param glob string = '/*.json'

resource real 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'a/*b'
}
`
	parsed := parseBicep(src)

	require.Len(t, parsed.parameters, 1)
	assert.Equal(t, "/*.json", parsed.parameters[0].defaultValue, "the `/*` inside the literal must survive")
	require.Len(t, parsed.resources, 1)
	assert.Equal(t, "'a/*b'", parsed.resources[0].name)
}

// Blanking preserves byte offsets and newlines so every line number the
// tokenizer reports (and the source excerpts built from them) stays accurate.
func TestStripBlockCommentsPreservesLineNumbers(t *testing.T) {
	src := `/*
a multi-line comment
spanning three lines
*/
param p string
`
	stripped := stripBlockComments(src)

	assert.Equal(t, len(src), len(stripped), "byte offsets must be preserved")
	assert.Equal(t, strings.Count(src, "\n"), strings.Count(stripped, "\n"), "newlines must be preserved")

	parsed := parseBicep(src)
	require.Len(t, parsed.parameters, 1)
	assert.Equal(t, 5, parsed.parameters[0].startLine, "the param is on source line 5")
}

// blanks returns as many spaces as s has bytes, so a table expectation reads
// as "this span is blanked" instead of a hand-counted run of spaces.
func blanks(s string) string { return strings.Repeat(" ", len(s)) }

func TestStripBlockComments(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"no comment is returned untouched", "param p string", "param p string"},
		{"inline comment is blanked", "param p string /* note */", "param p string " + blanks("/* note */")},
		{"line comment hides a block opener", "// see /* here\nparam p string", "// see /* here\nparam p string"},
		{"block comment inside a string is kept", "var v = '/* not a comment */'", "var v = '/* not a comment */'"},
		{"unterminated comment runs to EOF", "param p string\n/* unterminated", "param p string\n" + blanks("/* unterminated")},
		{"nested-looking markers close at the first */", "/* a /* b */ param p string", blanks("/* a /* b */") + " param p string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stripBlockComments(tc.in))
		})
	}
}

// scanState is the shared lexer for every bracket-balancing helper in the
// package, so it must not count delimiters inside a block comment.
func TestScanStateSkipsBlockComments(t *testing.T) {
	st := scanState{}
	st.feed("resource r 'T@v' = { /* } } } */")
	assert.Equal(t, 1, st.totalDepth(), "braces inside the comment must not count")

	multi := scanState{}
	multi.feed("var v = { /* opening { here")
	multi.feed("   still inside the comment }")
	multi.feed("*/ }")
	assert.Equal(t, 0, multi.totalDepth(), "a comment spanning lines keeps its state")
}
