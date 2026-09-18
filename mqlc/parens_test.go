// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/mqlc/parser"
)

func compileID(t *testing.T, code string) string {
	t.Helper()
	res, err := mqlc.Compile(code, nil, conf)
	require.NoError(t, err, "%q must compile", code)
	require.NotNil(t, res)
	require.NotNil(t, res.CodeV2)
	assert.NoError(t, mqlc.Invariants.Check(res))
	require.NotEmpty(t, res.CodeV2.Id)
	return res.CodeV2.Id
}

// TestParens_RedundantParensAreFree is the contract: a group that does not move
// the grouping has to leave no trace in the bytecode. The checksum is what says
// so, because it is what the upstream policy store keys on - a query whose
// checksum moves because someone added a paren is a query whose results stop
// matching their history.
func TestParens_RedundantParensAreFree(t *testing.T) {
	groups := [][]string{
		{"1 * (2 + 3)", "1*(2+3)", "1*(((2+3)))", "(1) * ((2 + 3))", "((1*(2+3)))"},
		{"1 + 2 * 3", "1 + (2 * 3)", "1+((2)*(3))", "(1 + 2 * 3)"},
		{"1 - 2 - 3", "(1-2)-3", "((1)-(2))-(3)"},
		{"users.where(name == 'x')", "users.where((name) == ('x'))", "(users).where(name == 'x')"},
		{"sshd.config.params['A']", "(sshd.config).params['A']", "(sshd.config.params)['A']"},
		{"true && false", "(true) && (false)", "(true && false)"},
	}

	for _, group := range groups {
		t.Run(group[0], func(t *testing.T) {
			want := compileID(t, group[0])
			for _, code := range group[1:] {
				assert.Equal(t, want, compileID(t, code), "%q must checksum like %q", code, group[0])
			}
		})
	}
}

// TestParens_MeaningfulParensChangeTheChecksum is the same contract read the
// other way. If these matched, the folding would be collapsing groups that
// actually carry a grouping.
func TestParens_MeaningfulParensChangeTheChecksum(t *testing.T) {
	pairs := [][2]string{
		{"1 + 2 * 3", "(1 + 2) * 3"},
		{"1 - 2 - 3", "1 - (2 - 3)"},
		{"12 / 2 * 3", "12 / (2 * 3)"},
		{"true || false && false", "(true || false) && false"},
	}

	for _, pair := range pairs {
		t.Run(pair[0]+" vs "+pair[1], func(t *testing.T) {
			assert.NotEqual(t, compileID(t, pair[0]), compileID(t, pair[1]))
		})
	}
}

// TestParens_EolQuery is the query that used to fail to compile, kept verbatim
// from TestCompiler_FailIfNoEntrypoints where it sat pinned as a known-broken
// case. Its parens are entirely redundant - `&&` already binds looser than `>`,
// which binds looser than `-` - so it is also the case that matters most: a user
// reaching for parens to say what MQL already meant must not get a different
// query out of it.
func TestParens_EolQuery(t *testing.T) {
	withParens := "(asset.eol.date - time.now() > 90*time.day) && (asset.eol.date - time.now() < 180*time.day)"
	withoutParens := "asset.eol.date - time.now() > 90*time.day && asset.eol.date - time.now() < 180*time.day"

	res, err := mqlc.Compile(withParens, nil, conf)
	require.NoError(t, err)
	require.NotNil(t, res.CodeV2)
	assert.NotEmpty(t, res.CodeV2.Entrypoints())

	assert.Equal(t, compileID(t, withoutParens), res.CodeV2.Id)
}

// TestParens_Errors covers what a group refuses at the compiler boundary.
func TestParens_Errors(t *testing.T) {
	tests := []string{
		"()",
		"(1, 2)",
		"1 * (2 + 3",
		"(1 + 2]",
		"1 * )2 + 3(",
	}

	for _, code := range tests {
		t.Run(code, func(t *testing.T) {
			_, err := mqlc.Compile(code, nil, conf)
			assert.Error(t, err)
		})
	}
}

// TestParens_IncompleteReachesTheShell: the shell decides whether to keep
// prompting by type-asserting the compile error to *parser.ErrIncomplete
// (cli/shell/model.go), not with errors.As. So an unterminated group has to come
// back out of Compile unwrapped, or a user typing a multi-line query gets a
// syntax error on the first line instead of a continuation prompt.
func TestParens_IncompleteReachesTheShell(t *testing.T) {
	_, err := mqlc.Compile("1 * (2 + 3", nil, conf)
	require.Error(t, err)
	_, ok := err.(*parser.ErrIncomplete)
	assert.True(t, ok, "want an unwrapped *parser.ErrIncomplete, got %T", err)
}

// TestParens_SignsAreOperators pins the lexer change parens needed. `1+2` used
// to lex as the numbers 1 and +2, so it compiled to two expressions and the
// query returned 2. Spacing is no longer load-bearing.
func TestParens_SignsAreOperators(t *testing.T) {
	pairs := [][2]string{
		{"1 + 2", "1+2"},
		{"1 - 2", "1-2"},
		{"3 * -1", "3*-1"},
	}

	for _, pair := range pairs {
		t.Run(pair[1], func(t *testing.T) {
			assert.Equal(t, compileID(t, pair[0]), compileID(t, pair[1]))
		})
	}
}

// TestParens_NewlineStartsAGroup covers the rule that keeps a line opening with
// `(` from being read as an argument list for the line above it.
func TestParens_NewlineStartsAGroup(t *testing.T) {
	assert.Equal(t,
		compileID(t, "a = 1\nb = 2\na + b"),
		compileID(t, "a = 1\nb = 2\n(a) + (b)"),
	)

	// the call form still needs its `(` on the same line
	assert.Equal(t,
		compileID(t, "users.where(name == 'x')"),
		compileID(t, "users.where(\n  name == 'x'\n)"),
	)
}
