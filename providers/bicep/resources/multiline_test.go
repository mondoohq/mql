// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func varByName(t *testing.T, p *parsedBicepFile, name string) parsedVariable {
	t.Helper()
	for _, v := range p.variables {
		if v.name == name {
			return v
		}
	}
	t.Fatalf("no variable named %q in %+v", name, p.variables)
	return parsedVariable{}
}

// A multi-line string opens no bracket, so a statement scanner that continues
// only while the bracket depth is positive cuts the declaration at the first
// newline. The remaining lines of the string then re-enter the scanner as
// top-level statements — and anything in them that looks like a declaration is
// parsed as one.
//
// This is the worst outcome in the taxonomy: the provider reports resources
// that are not in the deployment at all.
func TestMultilineStringDoesNotFabricateDeclarations(t *testing.T) {
	src := `var deployScript = '''
param ghostParam string = 'injected'
resource ghostRes 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: 'ghost'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
output ghostOut string = 'leaked'
'''

resource realRes 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: 'real'
}
`
	p := parseBicep(src)

	var resourceNames []string
	for _, r := range p.resources {
		resourceNames = append(resourceNames, r.symbolicName)
	}
	assert.Equal(t, []string{"realRes"}, resourceNames,
		"text inside a multi-line string must not be parsed as a resource declaration")

	assert.Empty(t, p.parameters, "text inside a multi-line string must not become a parameter")
	assert.Empty(t, p.outputs, "text inside a multi-line string must not become an output")
}

// The corollary: the multi-line string's own value must survive. A variable
// holding a deployment script, cloud-init payload, certificate, or policy blob
// previously read back as the bare opening delimiter.
func TestMultilineStringValueIsCaptured(t *testing.T) {
	src := `var script = '''
#!/bin/bash
echo hello
'''
var after = 'x'
`
	p := parseBicep(src)

	script := varByName(t, p, "script")
	assert.NotEqual(t, "'''", script.expression, "the multi-line string body must not be dropped")
	assert.Contains(t, script.expression, "echo hello")

	// The declaration that follows the string must still be parsed correctly.
	after := varByName(t, p, "after")
	assert.Equal(t, "'x'", after.expression)
}

// A multi-line default on a param is mangled the same way, which is worse than
// dropping it: the value reported is a fabricated fragment rather than an
// obvious absence.
func TestMultilineParamDefaultIsNotMangled(t *testing.T) {
	p := parseBicep("param p string = '''\nabc\n'''\n")
	require.Len(t, p.parameters, 1)
	assert.NotEqual(t, "'", p.parameters[0].defaultValue,
		"a multi-line default must not be reported as a stray quote")
	assert.Contains(t, p.parameters[0].defaultValue, "abc")
}

// Braces and brackets inside a multi-line string must not be counted by the
// statement scanner: an unbalanced one would otherwise swallow the rest of the
// file into a single statement.
func TestMultilineStringWithUnbalancedBraces(t *testing.T) {
	src := `var tpl = '''
{ "unclosed": [
'''
var after = 'y'
`
	p := parseBicep(src)
	after := varByName(t, p, "after")
	assert.Equal(t, "'y'", after.expression,
		"an unbalanced delimiter inside a multi-line string must not consume later declarations")
}

// The statement span reported for a multi-line declaration must cover the whole
// declaration, since it drives the source excerpt shown for a finding.
func TestMultilineStringStatementSpan(t *testing.T) {
	stmts := tokenizeBicep("var v = '''\na\nb\n'''\nvar after = 'x'\n")
	require.GreaterOrEqual(t, len(stmts), 2)
	assert.Equal(t, 1, stmts[0].startLine)
	assert.Equal(t, 4, strings.Count(stmts[0].text, "\n")+1,
		"the first statement must span all four lines of the multi-line declaration")
	assert.Equal(t, 5, stmts[1].startLine, "the following declaration starts on line 5")
}

// A multi-line string inside a resource body was already handled (the body's
// braces keep the statement open); guard against a regression.
func TestMultilineStringInsideResourceBody(t *testing.T) {
	src := `resource r 'Microsoft.Compute/virtualMachines@2021-03-01' = {
  name: 'vm'
  properties: {
    script: '''
    echo hi
    '''
  }
}
var after = 'z'
`
	p := parseBicep(src)
	require.Len(t, p.resources, 1)
	assert.Equal(t, "r", p.resources[0].symbolicName)
	assert.Contains(t, p.resources[0].body, "echo hi")
	varByName(t, p, "after")
}

// An unterminated multi-line string must not hang or panic; it consumes the
// rest of the file, which is the correct reading.
func TestUnterminatedMultilineString(t *testing.T) {
	assert.NotPanics(t, func() {
		p := parseBicep("var v = '''\nnever closed\nresource r 'T@1' = {\n")
		assert.Empty(t, p.resources,
			"an unterminated multi-line string runs to end of file, so nothing after it is a declaration")
	})
}
