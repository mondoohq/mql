// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A literal-union type has no bare word after the parameter name, so the old
// `(\w+)` type capture missed and `parseParameter` returned a zero-value
// struct that the caller appended anyway. The real declaration disappeared and
// the husk took its place.
func TestParseParameterUnionType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src      string
		wantName string
		typ      string
		def      string
	}{
		{
			name:     "single-quoted union with default",
			src:      "param sku 'Standard_LRS' | 'Premium_LRS' = 'Standard_LRS'\n",
			wantName: "sku",
			typ:      "'Standard_LRS' | 'Premium_LRS'",
			def:      "Standard_LRS",
		},
		{
			name:     "parenthesized union",
			src:      "param tier ('a'|'b') = 'a'\n",
			wantName: "tier",
			typ:      "('a'|'b')",
			def:      "a",
		},
		{
			name:     "union with no default",
			src:      "param sku 'Standard_LRS' | 'Premium_LRS'\n",
			wantName: "sku",
			typ:      "'Standard_LRS' | 'Premium_LRS'",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := parseBicep(tc.src)
			require.Len(t, parsed.parameters, 1, "the declaration must not be dropped")
			p := parsed.parameters[0]
			assert.Equal(t, tc.wantName, p.name)
			assert.Equal(t, tc.typ, p.typ)
			assert.Equal(t, tc.def, p.defaultValue)
		})
	}
}

// An array type dropped its `[]` suffix, and because the remainder then started
// with `[]` rather than `=`, the default was silently discarded too.
func TestParseParameterArrayType(t *testing.T) {
	parsed := parseBicep("param names string[] = ['a', 'b']\n")

	require.Len(t, parsed.parameters, 1)
	p := parsed.parameters[0]
	assert.Equal(t, "names", p.name)
	assert.Equal(t, "string[]", p.typ, "the array suffix belongs to the type")
	assert.Equal(t, "['a', 'b']", p.defaultValue, "the default must not be dropped")
}

func TestParseParameterNullableAndCustomTypes(t *testing.T) {
	parsed := parseBicep(`param a myType
param b myType?
param c int[]
`)
	require.Len(t, parsed.parameters, 3)
	assert.Equal(t, "myType", parsed.parameters[0].typ)
	assert.Equal(t, "myType?", parsed.parameters[1].typ)
	assert.Equal(t, "int[]", parsed.parameters[2].typ)
}

// A `param` with no type at all is malformed. It must be skipped rather than
// appended as an all-empty entry — two such husks share the __id
// `bicep.parameter:<path>:` and alias onto one cached resource.
func TestParseParameterMalformedIsSkipped(t *testing.T) {
	parsed := parseBicep(`param p
param q
param good string
`)

	require.Len(t, parsed.parameters, 1, "only the well-formed declaration survives")
	assert.Equal(t, "good", parsed.parameters[0].name)
	for _, p := range parsed.parameters {
		assert.NotEmpty(t, p.name, "no husk may be emitted")
	}
}

func TestParseOutputArrayType(t *testing.T) {
	parsed := parseBicep("output ids string[] = names\n")

	require.Len(t, parsed.outputs, 1, "the declaration must not be dropped")
	o := parsed.outputs[0]
	assert.Equal(t, "ids", o.name)
	assert.Equal(t, "string[]", o.typ)
	assert.Equal(t, "names", o.expression)
}

func TestParseOutputMalformedIsSkipped(t *testing.T) {
	parsed := parseBicep(`output broken
output alsoBroken string
output good string = 'x'
`)

	require.Len(t, parsed.outputs, 1, "an output with no assignment is malformed")
	assert.Equal(t, "good", parsed.outputs[0].name)
}

// The regression this guards: two husks carry identical (empty) names, and the
// __id is built as `bicep.parameter:<file>:<name>`, so they collapse onto one
// cached instance and the list silently contains duplicates of one entry.
func TestParseBicepNoDuplicateEmptyDeclarations(t *testing.T) {
	parsed := parseBicep(`param a 'x' | 'y' = 'x'
param b 'p' | 'q' = 'p'
output o1 string[] = a
output o2 string[] = b
`)

	require.Len(t, parsed.parameters, 2)
	assert.Equal(t, "a", parsed.parameters[0].name)
	assert.Equal(t, "b", parsed.parameters[1].name)
	assert.NotEqual(t, parsed.parameters[0].name, parsed.parameters[1].name)

	require.Len(t, parsed.outputs, 2)
	assert.Equal(t, "o1", parsed.outputs[0].name)
	assert.Equal(t, "o2", parsed.outputs[1].name)
}

func TestSplitDeclAtEquals(t *testing.T) {
	for _, tc := range []struct {
		name          string
		in            string
		before, after string
		ok            bool
	}{
		{"simple", "string = 'x'", "string", "'x'", true},
		{"no assignment", "string", "", "", false},
		{"equals inside a string literal", "string = 'a=b'", "string", "'a=b'", true},
		{"union type before the assignment", "'a' | 'b' = 'a'", "'a' | 'b'", "'a'", true},
		{"array type", "string[] = ['a']", "string[]", "['a']", true},
		{"comparison in the value", "bool = a == b", "bool", "a == b", true},
		{"lambda arrow in the value", "object = map(xs, x => x)", "object", "map(xs, x => x)", true},
		{"equals inside parens is not top level", "('a=b') = 'x'", "('a=b')", "'x'", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after, ok := splitDeclAtEquals(tc.in)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.before, before)
			assert.Equal(t, tc.after, after)
		})
	}
}
