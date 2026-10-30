// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func firstResource(t *testing.T, src string) parsedResource {
	t.Helper()
	p := parseBicep(src)
	require.Len(t, p.resources, 1, "expected exactly one resource in:\n%s", src)
	return p.resources[0]
}

func firstParam(t *testing.T, src string) parsedParameter {
	t.Helper()
	p := parseBicep(src)
	require.Len(t, p.parameters, 1, "expected exactly one parameter in:\n%s", src)
	return p.parameters[0]
}

// Tags written inline on one line are valid Bicep and common. A per-line
// anchored regex matched none of them, so a correctly tagged resource reported
// no tags at all and a governance policy failed it.
func TestExtractTagsLayouts(t *testing.T) {
	cases := []struct {
		name string
		tags string
		want map[string]string
	}{
		{
			name: "inline multiple pairs",
			tags: "  tags: { env: 'prod', owner: 'platform' }",
			want: map[string]string{"env": "prod", "owner": "platform"},
		},
		{
			name: "inline single pair",
			tags: "  tags: { env: 'prod' }",
			want: map[string]string{"env": "prod"},
		},
		{
			name: "multi-line newline separated",
			tags: "  tags: {\n    env: 'prod'\n    owner: 'platform'\n  }",
			want: map[string]string{"env": "prod", "owner": "platform"},
		},
		{
			name: "multi-line comma separated",
			tags: "  tags: {\n    env: 'prod',\n    owner: 'platform'\n  }",
			want: map[string]string{"env": "prod", "owner": "platform"},
		},
		{
			name: "trailing line comment",
			tags: "  tags: {\n    env: 'prod' // the environment\n    owner: 'platform'\n  }",
			want: map[string]string{"env": "prod", "owner": "platform"},
		},
		{
			name: "quoted key",
			tags: "  tags: { 'cost-center': '1234' }",
			want: map[string]string{"cost-center": "1234"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'mysa'\n" + c.tags + "\n}\n"
			assert.Equal(t, c.want, firstResource(t, src).tags)
		})
	}
}

// Expression-valued tags stay out of the literal map, as documented.
func TestExtractTagsSkipsExpressions(t *testing.T) {
	src := "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'mysa'\n  tags: { env: toLower(envName), owner: 'platform' }\n}\n"
	assert.Equal(t, map[string]string{"owner": "platform"}, firstResource(t, src).tags)
}

// The condition scanner counted parentheses without honoring string literals,
// so a `)` inside a quoted value truncated the expression.
func TestExtractConditionIsStringAware(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"resource r 'T@2020-01-01' = if (env == 'prod') {", "env == 'prod'"},
		{"resource r 'T@2020-01-01' = if (tag == 'a)b') {", "tag == 'a)b'"},
		{"resource r 'T@2020-01-01' = if (contains(name, ')')) {", "contains(name, ')')"},
		{"resource r 'T@2020-01-01' = {", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, extractCondition(c.line), "input: %s", c.line)
	}
}

// A default that merely begins and ends with a quote is not a single literal;
// stripping the outer quotes corrupted it into an unbalanced string.
func TestParameterDefaultQuoteStripping(t *testing.T) {
	assert.Equal(t, "eastus", firstParam(t, "param loc string = 'eastus'\n").defaultValue)

	got := firstParam(t, "param sku string = 'prod' == env ? 'Premium' : 'Standard'\n").defaultValue
	assert.Equal(t, "'prod' == env ? 'Premium' : 'Standard'", got,
		"an expression that only starts and ends with a quote must not be unquoted")

	assert.Equal(t, "isProd ? 'prod' : 'dev'",
		firstParam(t, "param env string = isProd ? 'prod' : 'dev'\n").defaultValue)
}

// A description containing an escaped quote matched nothing, so the whole
// description read as absent.
func TestDescriptionDecoratorWithEscapedQuote(t *testing.T) {
	assert.Equal(t, "Plain description",
		firstParam(t, "@description('Plain description')\nparam p string\n").description)

	got := firstParam(t, "@description('The VM\\'s admin username')\nparam adminUser string\n").description
	assert.NotEmpty(t, got, "an escaped quote must not blank the description")
	assert.Contains(t, got, "admin username")
}

// An allowed-values list containing a `]` inside a literal matched nothing, so
// the entire constraint read as absent and a policy asserting it passed
// vacuously.
func TestAllowedDecoratorWithBracketInLiteral(t *testing.T) {
	assert.Equal(t, []string{"a", "c"},
		firstParam(t, "@allowed([ 'a', 'c' ])\nparam x string\n").allowed)

	assert.Equal(t, []string{"a]b", "c"},
		firstParam(t, "@allowed([ 'a]b', 'c' ])\nparam x string\n").allowed)
}

// A single-quoted string cannot span lines in Bicep. Leaking the in-string
// state across a newline turned the rest of a resource body into one string
// value, so its properties read as empty and an audit over them passed
// vacuously.
func TestUnterminatedStringDoesNotSwallowResourceBody(t *testing.T) {
	src := `resource r 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'unterminated
  location: 'eastus'
  properties: {
    allowBlobPublicAccess: true
  }
}
`
	r := firstResource(t, src)
	assert.Equal(t, "'eastus'", r.location,
		"a declaration after an unterminated string must still parse")

	props := parseBicepObject(bodyObjectInner(r.body))
	assert.Contains(t, props, "properties",
		"the resource body must not collapse into a single string value")
}
