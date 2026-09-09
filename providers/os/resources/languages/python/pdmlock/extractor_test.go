// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pdmlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSimple(t *testing.T) {
	f, err := os.Open("testdata/simple.toml")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/simple.toml")
	require.NoError(t, err)

	assert.Nil(t, bom.Root())
	assert.Nil(t, bom.Direct())

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 5)

	django := pkgs.Find("django")
	require.NotNil(t, django)
	assert.Equal(t, "4.2.7", django.Version)
	assert.Equal(t, "pkg:pypi/django@4.2.7", django.Purl)

	pytest := pkgs.Find("pytest")
	require.NotNil(t, pytest)
	assert.Equal(t, "7.4.3", pytest.Version)
}

func TestName(t *testing.T) {
	e := &Extractor{}
	assert.Equal(t, "pdmlock", e.Name())
}

// TestPdmLockDependencyEdges pins the pdm package->package graph. pdm writes
// each package's dependencies as PEP 508 requirement strings and the extractor
// read past them, so a pdm project supplied no edges at all.
func TestPdmLockDependencyEdges(t *testing.T) {
	f, err := os.Open("testdata/simple.toml")
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "pdm.lock")
	require.NoError(t, err)
	pkgs := bom.Transitive()

	requests := pkgs.Find("requests")
	require.NotNil(t, requests)
	// The edge target is the version pdm RESOLVED (certifi 2024.2.2), never the
	// `>=2017.4.17` constraint written in the requirement: a purl from the
	// constraint names a package this lock did not resolve, so the edge would
	// point at nothing. `not-locked` has no entry and is dropped.
	assert.Equal(t, []string{
		"pkg:pypi/certifi@2024.2.2",
		"pkg:pypi/charset-normalizer@3.3.2",
	}, requests.DependsOn)

	assert.Nil(t, pkgs.Find("certifi").DependsOn)
	assert.Nil(t, pkgs.Find("pytest").DependsOn)
	assert.Nil(t, pkgs.Find("not-locked"), "an unresolved requirement must not become a package")
}

func TestPep508Name(t *testing.T) {
	cases := map[string]string{
		"urllib3<3,>=1.21.1":           "urllib3",
		"certifi>=2017.4.17":           "certifi",
		"charset_normalizer<4,>=2":     "charset_normalizer",
		"requests[socks]>=2.0":         "requests",
		"idna":                         "idna",
		"  spaced  >=1 ":               "spaced",
		`foo ; python_version < "3.9"`: "foo",
		"typing-extensions!=4.0.0":     "typing-extensions",
		"zope.interface>=5":            "zope.interface",
		"":                             "",
		"(bad":                         "",
	}
	for in, want := range cases {
		assert.Equal(t, want, pep508Name(in), "pep508Name(%q)", in)
	}
}
