// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequiresTxt(t *testing.T) {
	data := `
nose>=1.2
Mock>=1.0
pycryptodome

[crypto]
pycryptopp>=0.5.12

[cryptography]
cryptography
`

	dependencies, err := ParseRequiresTxtDependencies(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, []string{"nose", "Mock", "pycryptodome"}, dependencies)
}

func TestParseRequirementsTxt_PinnedVersions(t *testing.T) {
	data := `
openai==1.30.0
transformers==4.40.0
requests>=2.32.0
numpy
torch===2.3.0
`
	reqs, err := ParseRequirementsTxt(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, reqs, 5)

	assert.Equal(t, "openai", reqs[0].Name)
	assert.Equal(t, "1.30.0", reqs[0].Version)

	assert.Equal(t, "transformers", reqs[1].Name)
	assert.Equal(t, "4.40.0", reqs[1].Version)

	assert.Equal(t, "requests", reqs[2].Name)
	assert.Equal(t, "", reqs[2].Version, "non-pinned should have empty version")

	assert.Equal(t, "numpy", reqs[3].Name)
	assert.Equal(t, "", reqs[3].Version, "bare name should have empty version")

	assert.Equal(t, "torch", reqs[4].Name)
	assert.Equal(t, "2.3.0", reqs[4].Version, "=== should also pin")
}

func TestParseRequirementsTxt_Comments(t *testing.T) {
	data := `
# This is a comment
openai==1.30.0  # inline comment
# another comment
torch==2.3.0
`
	reqs, err := ParseRequirementsTxt(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	assert.Equal(t, "openai", reqs[0].Name)
	assert.Equal(t, "torch", reqs[1].Name)
}

func TestParseRequirementsTxt_LineContinuation(t *testing.T) {
	data := `openai==\
1.30.0
torch==2.3.0
`
	reqs, err := ParseRequirementsTxt(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	assert.Equal(t, "openai", reqs[0].Name)
	assert.Equal(t, "1.30.0", reqs[0].Version)
}

func TestParseRequirementsTxt_Extras(t *testing.T) {
	data := `requests[security]==2.8.0
langchain[llm,tools]==0.2.0
`
	reqs, err := ParseRequirementsTxt(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, reqs, 2)

	assert.Equal(t, "requests", reqs[0].Name)
	assert.Equal(t, "2.8.0", reqs[0].Version)
	assert.Equal(t, []string{"security"}, reqs[0].Extras)

	assert.Equal(t, "langchain", reqs[1].Name)
	assert.Equal(t, []string{"llm", "tools"}, reqs[1].Extras)
}

func TestParseRequirementsTxt_SkipOptions(t *testing.T) {
	data := `
-r other-requirements.txt
--index-url https://pypi.org/simple
-e git+https://github.com/user/project.git#egg=project
openai==1.30.0
`
	reqs, err := ParseRequirementsTxt(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "openai", reqs[0].Name)
}

func TestParseRequirementsTxt_WildcardNotPinned(t *testing.T) {
	data := `requests==2.8.*
`
	reqs, err := ParseRequirementsTxt(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "requests", reqs[0].Name)
	assert.Equal(t, "", reqs[0].Version, "wildcard version should not be pinned")
}

func TestParseRequirementsTxt_Empty(t *testing.T) {
	reqs, err := ParseRequirementsTxt(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, reqs)
}

func TestParsePinnedVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"==1.30.0", "1.30.0"},
		{"===2.3.0", "2.3.0"},
		{">=1.0", ""},
		{"~=1.0", ""},
		{"==2.8.*", ""},
		{">=1.0,<2.0", ""},
		{"", ""},
		{"  ==1.0  ", "1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, parsePinnedVersion(tt.input))
		})
	}
}

func TestParseRequiresTxtDependenciesKeepsNamesAfterLongLine(t *testing.T) {
	content := "requests\n# " + strings.Repeat("x", 70000) + "\nurllib3\n"
	deps, err := ParseRequiresTxtDependencies(strings.NewReader(content))
	require.NoError(t, err)
	assert.Contains(t, deps, "urllib3")
}

func TestParseRequiresTxtDependenciesReturnsReadError(t *testing.T) {
	_, err := ParseRequiresTxtDependencies(io.MultiReader(strings.NewReader("requests\n"), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}

// A long hash or URL line must not end the parse: before it would fail the
// whole file with bufio.ErrTooLong.
func TestParseRequirementsTxtKeepsRequirementsAfterLongLine(t *testing.T) {
	content := "requests==2.31.0\n# " + strings.Repeat("x", 70000) + "\nurllib3==2.0.7\n"
	reqs, err := ParseRequirementsTxt(strings.NewReader(content))
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	assert.Equal(t, "urllib3", reqs[1].Name)
}
