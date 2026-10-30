// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
)

// strictConf mirrors `conf` with ADR 043 strict mode turned on.
func strictConf() mqlc.CompilerConfig {
	c := conf
	c.Strict = true
	return c
}

// nullabilityOf returns the marker on each function chunk of the first block, in
// emission order, so a test can pin which link in a chain carries which marker.
func nullabilityOf(t *testing.T, code string, c mqlc.CompilerConfig) []llx.Function_Nullability {
	t.Helper()
	res, err := mqlc.Compile(code, nil, c)
	require.NoError(t, err)
	require.NotNil(t, res.CodeV2)
	require.NotEmpty(t, res.CodeV2.Blocks)

	var out []llx.Function_Nullability
	for _, chunk := range res.CodeV2.Blocks[0].Chunks {
		if chunk.Function == nil {
			continue
		}
		out = append(out, chunk.Function.Nullability)
	}
	return out
}

// TestStrict_offMarksNothing is the compatibility guarantee: a non-strict
// compile must leave every chunk unmarked, which is what keeps existing
// checksums byte-identical.
func TestStrict_offMarksNothing(t *testing.T) {
	for _, code := range []string{
		"sshd.config.params",
		"sshd.config.params['UsePAM']",
		"sshd.config?.params",
		"sshd.config.params?['UsePAM']",
		"sshd.config { params }",
	} {
		t.Run(code, func(t *testing.T) {
			for _, n := range nullabilityOf(t, code, conf) {
				assert.Equal(t, llx.Function_NULLABILITY_UNSPECIFIED, n)
			}
		})
	}
}

// TestStrict_marksEveryLink checks that strict mode marks each dereference
// required, and that `?` flips exactly the link it is attached to - the one on
// its left - and no others. A sticky `?` would show up here as extra optional
// markers.
//
// Note what is absent: a bare resource root like `sshd.config` compiles to a
// chunk with no Function at all, so it carries no marker and is filtered out by
// nullabilityOf. That is harmless - a global resource has no binding and cannot
// be null - but it does mean a `?` written directly on one is a silent no-op.
func TestStrict_marksEveryLink(t *testing.T) {
	req := llx.Function_NULLABILITY_REQUIRED
	opt := llx.Function_NULLABILITY_OPTIONAL

	tests := []struct {
		code     string
		expected []llx.Function_Nullability
	}{
		{"sshd.config.params", []llx.Function_Nullability{req}},
		{"sshd.config.file.path", []llx.Function_Nullability{req, req}},
		// the mark guards `file`, the link to its left ...
		{"sshd.config.file?.path", []llx.Function_Nullability{opt, req}},
		// ... and not the link to its right: `path` stays required, so a null
		// `file` still errors. This is the non-sticky property, and it is what
		// makes the semantics match optional chaining in JavaScript.
		{"sshd.config.file?.path?", []llx.Function_Nullability{opt, opt}},
		// trailing `?` marks the last link, the only way to make a terminal
		// lookup optional
		{"sshd.config.params?", []llx.Function_Nullability{opt}},
		// a key lookup is a link like any other
		{"sshd.config.params['UsePAM']", []llx.Function_Nullability{req, req}},
		{"sshd.config.params?['UsePAM']", []llx.Function_Nullability{opt, req}},
		{"sshd.config.params['UsePAM']?", []llx.Function_Nullability{req, opt}},
	}

	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			assert.Equal(t, test.expected, nullabilityOf(t, test.code, strictConf()))
		})
	}
}

// TestStrict_operatorsStayUnmarked is what makes `a["key"] == null` work, and
// what keeps `a.f == "no"` returning false rather than erroring on a null `f`.
// Operators are compiled outside the access-chain path, so they must never pick
// up a marker (ADR 043 §2).
func TestStrict_operatorsStayUnmarked(t *testing.T) {
	res, err := mqlc.Compile(`sshd.config.params['UsePAM'] == null`, nil, strictConf())
	require.NoError(t, err)

	chunks := res.CodeV2.Blocks[0].Chunks
	last := chunks[len(chunks)-1]
	require.NotNil(t, last.Function)
	assert.Contains(t, last.Id, "==", "last chunk should be the comparison")
	assert.Equal(t, llx.Function_NULLABILITY_UNSPECIFIED, last.Function.Nullability,
		"comparison operators must stay unmarked so null stays a legal operand")
}

// TestStrict_changesChecksums pins the reason nullability is folded into the
// chunk checksum: without it these compile to identical bytes while meaning
// different things, and collide in any cache keyed on the code id.
func TestStrict_changesChecksums(t *testing.T) {
	const code = "sshd.config.file.path"

	lenient, err := mqlc.Compile(code, nil, conf)
	require.NoError(t, err)
	strict, err := mqlc.Compile(code, nil, strictConf())
	require.NoError(t, err)
	guarded, err := mqlc.Compile("sshd.config.file?.path", nil, strictConf())
	require.NoError(t, err)

	assert.NotEqual(t, lenient.CodeV2.Id, strict.CodeV2.Id,
		"strict and non-strict compilations must not share a code id")
	assert.NotEqual(t, strict.CodeV2.Id, guarded.CodeV2.Id,
		"a guarded chain must not share a code id with an unguarded one")
}
