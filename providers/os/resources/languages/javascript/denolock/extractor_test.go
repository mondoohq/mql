// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package denolock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hex encoding of the sha512 SRI used for chalk in the v4 fixture.
const chalkSHA512Hex = "e4ce7706c3aa711781335d0213349a182e2575d6f150ccbdbfe88b43c18f425d9ddbb9dbf32b8df061ebf0986d2997b71f7008201bec7590df0aa3bc96a19ae9"

func TestParseV4(t *testing.T) {
	f, err := os.Open("testdata/v4.deno.lock")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/v4.deno.lock")
	require.NoError(t, err)

	assert.Nil(t, bom.Root())
	assert.Nil(t, bom.Direct())

	pkgs := bom.Transitive()
	// chalk (two keys collapse to one), @babel/core, @std/assert(jsr) → 3.
	assert.Len(t, pkgs, 3)

	chalk := pkgs.Find("chalk")
	require.NotNil(t, chalk)
	assert.Equal(t, "5.3.0", chalk.Version)
	assert.Equal(t, "pkg:npm/chalk@5.3.0", chalk.Purl)
	require.Len(t, chalk.Hashes, 1)
	assert.Equal(t, "SHA-512", chalk.Hashes[0].Alg)
	assert.Equal(t, chalkSHA512Hex, chalk.Hashes[0].Value)

	// Scoped npm package keeps its scope in the purl namespace.
	babel := pkgs.Find("@babel/core")
	require.NotNil(t, babel)
	assert.Equal(t, "7.24.0", babel.Version)
	assert.Equal(t, "pkg:npm/%40babel/core@7.24.0", babel.Purl)

	// JSR package: pkg:npm with a jsr repository_url qualifier.
	jsr := pkgs.Find("@std/assert")
	require.NotNil(t, jsr)
	assert.Contains(t, jsr.Purl, "pkg:npm/%40std/assert@1.0.0")
	// The purl library percent-encodes the qualifier value.
	assert.Contains(t, jsr.Purl, "repository_url=https:%2F%2Fjsr.io")
}

func TestParseV3(t *testing.T) {
	f, err := os.Open("testdata/v3.deno.lock")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/v3.deno.lock")
	require.NoError(t, err)

	pkgs := bom.Transitive()
	// npm packages nested under `packages` (v3) are found; remote URLs are not packages.
	assert.Len(t, pkgs, 1)
	cowsay := pkgs.Find("cowsay")
	require.NotNil(t, cowsay)
	assert.Equal(t, "1.5.0", cowsay.Version)
	assert.Equal(t, "pkg:npm/cowsay@1.5.0", cowsay.Purl)
}

func TestSplitNameVersion(t *testing.T) {
	tests := []struct{ key, name, version string }{
		{"chalk@5.3.0", "chalk", "5.3.0"},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0"},
		{"chalk@5.3.0_supports-color@9.0.0", "chalk", "5.3.0"},
		{"@std/assert@1.0.0", "@std/assert", "1.0.0"},
	}
	for _, tt := range tests {
		name, version := splitNameVersion(tt.key)
		assert.Equal(t, tt.name, name, "key: %s", tt.key)
		assert.Equal(t, tt.version, version, "key: %s", tt.key)
	}
}

func TestName(t *testing.T) {
	e := &Extractor{}
	assert.Equal(t, "deno.lock", e.Name())
}
