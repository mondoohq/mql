// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pnpmlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseV5(t *testing.T) {
	f, err := os.Open("testdata/v5.yaml")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/v5.yaml")
	require.NoError(t, err)

	assert.Nil(t, bom.Root())
	assert.Nil(t, bom.Direct())

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 4)

	express := pkgs.Find("express")
	require.NotNil(t, express)
	assert.Equal(t, "4.18.2", express.Version)
	assert.Equal(t, "pkg:npm/express@4.18.2", express.Purl)
	// dependency edges resolve to the depended-on packages' purls
	assert.Equal(t, []string{"pkg:npm/accepts@1.3.8", "pkg:npm/body-parser@1.20.1"}, express.DependsOn)
	// a prod (non-dev) package
	assert.Equal(t, "prod", express.Scope)

	typesNode := pkgs.Find("@types/node")
	require.NotNil(t, typesNode)
	assert.Equal(t, "20.10.0", typesNode.Version)
	assert.Equal(t, "pkg:npm/%40types/node@20.10.0", typesNode.Purl)
	// dev: true in the lockfile → dev scope
	assert.Equal(t, "dev", typesNode.Scope)
}

func TestParseV9(t *testing.T) {
	f, err := os.Open("testdata/v9.yaml")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/v9.yaml")
	require.NoError(t, err)

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 4)

	express := pkgs.Find("express")
	require.NotNil(t, express)
	assert.Equal(t, "4.18.2", express.Version)

	typesNode := pkgs.Find("@types/node")
	require.NotNil(t, typesNode)
	assert.Equal(t, "20.10.0", typesNode.Version)
}

func TestParseV6(t *testing.T) {
	f, err := os.Open("testdata/v6.yaml")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/v6.yaml")
	require.NoError(t, err)

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 3)

	scopedPkg := pkgs.Find("@scope/utils")
	require.NotNil(t, scopedPkg)
	assert.Equal(t, "2.0.0", scopedPkg.Version)
}

func TestParsePnpmV5Key(t *testing.T) {
	tests := []struct {
		key     string
		name    string
		version string
		ok      bool
	}{
		{"/express/4.18.2", "express", "4.18.2", true},
		{"/@types/node/20.10.0", "@types/node", "20.10.0", true},
		{"/pkg/1.0.0_peer@2.0.0", "pkg", "1.0.0", true},
		{"/pkg/1.0.0(react@18.0.0)", "pkg", "1.0.0", true},
		{"", "", "", false},
		{"/", "", "", false},
	}

	for _, tt := range tests {
		name, ver, ok := parsePnpmV5Key(tt.key)
		assert.Equal(t, tt.ok, ok, "key: %s", tt.key)
		if ok {
			assert.Equal(t, tt.name, name, "key: %s", tt.key)
			assert.Equal(t, tt.version, ver, "key: %s", tt.key)
		}
	}
}

func TestParseAtSeparatedKey(t *testing.T) {
	tests := []struct {
		key     string
		name    string
		version string
		ok      bool
	}{
		{"express@4.18.2", "express", "4.18.2", true},
		{"@types/node@20.10.0", "@types/node", "20.10.0", true},
		{"react-dom@18.2.0(react@18.2.0)", "react-dom", "18.2.0", true},
		{"noversion", "", "", false},
	}

	for _, tt := range tests {
		name, ver, ok := parseAtSeparatedKey(tt.key)
		assert.Equal(t, tt.ok, ok, "key: %s", tt.key)
		if ok {
			assert.Equal(t, tt.name, name, "key: %s", tt.key)
			assert.Equal(t, tt.version, ver, "key: %s", tt.key)
		}
	}
}

func TestParsePnpmV6Key(t *testing.T) {
	tests := []struct {
		key     string
		name    string
		version string
		ok      bool
	}{
		{"/express@4.18.2", "express", "4.18.2", true},
		{"/@scope/utils@2.0.0", "@scope/utils", "2.0.0", true},
		{"/react-dom@18.2.0(react@18.2.0)", "react-dom", "18.2.0", true},
		{"", "", "", false},
		{"/", "", "", false},
	}

	for _, tt := range tests {
		name, ver, ok := parsePnpmV6Key(tt.key)
		assert.Equal(t, tt.ok, ok, "key: %s", tt.key)
		if ok {
			assert.Equal(t, tt.name, name, "key: %s", tt.key)
			assert.Equal(t, tt.version, ver, "key: %s", tt.key)
		}
	}
}

func TestParseV5Tarball(t *testing.T) {
	f, err := os.Open("testdata/v5-tarball.yaml")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/v5-tarball.yaml")
	require.NoError(t, err)

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 2)

	// Tarball/git package with explicit name/version fields and unparseable key.
	scopedPkg := pkgs.Find("@my-scope/my-package")
	require.NotNil(t, scopedPkg)
	assert.Equal(t, "1.0.0", scopedPkg.Version)
}

func TestName(t *testing.T) {
	e := &Extractor{}
	assert.Equal(t, "pnpmlock", e.Name())
}
