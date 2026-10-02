// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
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

	dependencies, err := ParseRequiresTxtDependencies(strings.NewReader(data), python.MarkerEnvironment{"extra": ""})
	require.NoError(t, err)
	assert.Equal(t, []string{"nose", "Mock", "pycryptodome"}, dependencies)
}

// egg-info requires.txt files from the Debian sweep hosts. A "[:marker]"
// section is required wherever its marker holds; parsing used to stop at the
// first section, so keyring's secretstorage was never a dependency.
func TestRequiresTxtMarkerSections(t *testing.T) {
	read := func(name string) *os.File {
		f, err := os.Open("testdata/" + name)
		require.NoError(t, err)
		t.Cleanup(func() { f.Close() })
		return f
	}

	linux := python.SiteMarkerEnvironment("/usr/lib/python3/dist-packages", "linux")
	deps, err := ParseRequiresTxtDependencies(read("keyring-10.1-requires.txt"), linux)
	require.NoError(t, err)
	assert.Equal(t, []string{"secretstorage"}, deps, "the win32 section does not apply on Linux")

	// "[docs]" and "[jinja2]" are extras; the CPython section's implementation
	// is unknown and Debian's dist-packages path names only Python 3
	deps, err = ParseRequiresTxtDependencies(read("ruamel.yaml-0.17.21-requires.txt"), linux)
	require.NoError(t, err)
	assert.Equal(t, []string{"ruamel.yaml.clib"}, deps)

	py312 := python.SiteMarkerEnvironment("/usr/lib/python3.12/site-packages", "linux")
	deps, err = ParseRequiresTxtDependencies(read("ruamel.yaml-0.17.21-requires.txt"), py312)
	require.NoError(t, err)
	assert.Empty(t, deps, "python_version<\"3.11\" is false on 3.12")
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
