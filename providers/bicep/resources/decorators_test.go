// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Bicep lets every built-in decorator be written through the `sys` namespace,
// which is required when a user-defined symbol shadows the bare name. Reading
// `@sys.secure()` as "not secure" is the dangerous direction: a "secrets must
// be @secure()" policy reports a false violation, and its inverse a false pass.
func TestParseParameterSysQualifiedDecorators(t *testing.T) {
	for _, prefix := range []string{"@", "@sys."} {
		t.Run(prefix, func(t *testing.T) {
			src := prefix + "secure()\n" +
				prefix + "description('the admin password')\n" +
				prefix + "minLength(8)\n" +
				prefix + "maxLength(64)\n" +
				"param pw string\n"

			parsed := parseBicep(src)
			require.Len(t, parsed.parameters, 1)
			p := parsed.parameters[0]

			assert.Equal(t, "pw", p.name)
			assert.True(t, p.secure, "%ssecure() must set secure", prefix)
			assert.Equal(t, "the admin password", p.description)
			require.NotNil(t, p.minLength)
			assert.Equal(t, int64(8), *p.minLength)
			require.NotNil(t, p.maxLength)
			assert.Equal(t, int64(64), *p.maxLength)
		})
	}
}

func TestParseParameterSysQualifiedAllowedAndValueBounds(t *testing.T) {
	src := `@sys.allowed([
  'Standard_LRS'
  'Premium_LRS'
])
@sys.minValue(1)
@sys.maxValue(10)
param sku string
`
	parsed := parseBicep(src)
	require.Len(t, parsed.parameters, 1)
	p := parsed.parameters[0]

	assert.Equal(t, []string{"Standard_LRS", "Premium_LRS"}, p.allowed)
	require.NotNil(t, p.minValue)
	assert.Equal(t, int64(1), *p.minValue)
	require.NotNil(t, p.maxValue)
	assert.Equal(t, int64(10), *p.maxValue)
}

func TestParseTypeSysQualifiedExportAndDiscriminator(t *testing.T) {
	src := `@sys.export()
@sys.discriminator('kind')
type shape = { kind: string }
`
	parsed := parseBicep(src)
	require.Len(t, parsed.types, 1)

	assert.True(t, parsed.types[0].exported, "@sys.export() must mark the type exported")
	assert.Equal(t, "kind", parsed.types[0].discriminator)
}

// `#disable-next-line` is a first-class Bicep construct and idiomatically sits
// immediately above the declaration, below its decorators. The tokenizer only
// skipped blank and `//` lines between a decorator and its statement, so the
// directive detached every decorator onto a phantom empty statement — taking
// `secure`, `description` and the bounds with it.
func TestTokenizeDecoratorsSurviveDisableNextLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			name: "directive between the decorators and the declaration",
			src: `@secure()
@description('pw')
#disable-next-line secure-parameter-default
param pw string = ''
`,
		},
		{
			name: "directive between two decorators",
			src: `@secure()
#disable-next-line BCP081
@description('pw')
param pw string = ''
`,
		},
		{
			name: "directive above the decorators",
			src: `#disable-next-line secure-parameter-default
@secure()
@description('pw')
param pw string = ''
`,
		},
		{
			name: "directive with a trailing comment",
			src: `@secure()
@description('pw')
#disable-next-line secure-parameter-default // intentional
param pw string = ''
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := parseBicep(tc.src)

			require.Len(t, parsed.parameters, 1, "the param must still be parsed")
			p := parsed.parameters[0]
			assert.Equal(t, "pw", p.name)
			assert.Equal(t, "string", p.typ)
			assert.True(t, p.secure, "@secure() must stay attached across the directive")
			assert.Equal(t, "pw", p.description, "@description() must stay attached too")
		})
	}
}

// A `#` directive on its own must not become an empty-keyword statement — that
// is what dropped the decorators onto a phantom declaration.
func TestTokenizeBicepSkipsDirectiveLines(t *testing.T) {
	stmts := tokenizeBicep(`#disable-next-line no-unused-params

@secure()
#disable-next-line secure-parameter-default
param pw string = ''
`)

	require.Len(t, stmts, 1, "only the param statement should be emitted")
	assert.Equal(t, "param", stmts[0].keyword)
	assert.Equal(t, []string{"@secure()"}, stmts[0].decorators)
}
