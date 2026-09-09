// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uvlock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSimple(t *testing.T) {
	f, err := os.Open("testdata/simple.lock")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/simple.lock")
	require.NoError(t, err)

	root := bom.Root()
	require.NotNil(t, root)
	assert.Equal(t, "my-project", root.Name)
	assert.Equal(t, "0.1.0", root.Version)

	assert.Nil(t, bom.Direct())

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 5)

	django := pkgs.Find("django")
	require.NotNil(t, django)
	assert.Equal(t, "4.2.7", django.Version)
	assert.Equal(t, "pkg:pypi/django@4.2.7", django.Purl)
	assert.Len(t, django.EvidenceList, 1)
}

func TestName(t *testing.T) {
	e := &Extractor{}
	assert.Equal(t, "uvlock", e.Name())
}

// TestUvLockDependencyEdges pins the uv package->package graph. uv writes each
// package's own dependencies into every lock and the extractor read past them,
// so a uv project supplied no edges at all and every transitive in it stayed
// undetermined — neither reachable nor rulable out.
func TestUvLockDependencyEdges(t *testing.T) {
	f, err := os.Open("testdata/simple.lock")
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "uv.lock")
	require.NoError(t, err)
	pkgs := bom.Transitive()

	requests := pkgs.Find("requests")
	require.NotNil(t, requests)
	// certifi and urllib3 are runtime deps; charset-normalizer arrives through
	// the `socks` extra and is folded in on purpose (see OptionalDependencies).
	// `not-locked` is named and never resolved, so it is dropped.
	assert.Equal(t, []string{
		"pkg:pypi/certifi@2024.2.2",
		"pkg:pypi/charset-normalizer@3.3.2",
		"pkg:pypi/urllib3@2.1.0",
	}, requests.DependsOn)

	// A leaf states none and carries none, so "depends on nothing" and "was
	// never read" stay distinct downstream.
	assert.Nil(t, pkgs.Find("certifi").DependsOn)
	assert.Nil(t, pkgs.Find("django").DependsOn)
}

// TestUvLockNormalizesDependencyNames: the lock spells the extra's dependency
// `charset_normalizer` and the package entry `charset-normalizer`. PEP 503
// treats them as one name, and an edge keyed on the raw spelling would resolve
// to nothing.
func TestUvLockNormalizesDependencyNames(t *testing.T) {
	f, err := os.Open("testdata/simple.lock")
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "uv.lock")
	require.NoError(t, err)

	assert.Contains(t, bom.Transitive().Find("requests").DependsOn,
		"pkg:pypi/charset-normalizer@3.3.2",
		"an underscore spelling must resolve to the normalized entry")
}

// TestUvLockDropsUnresolvedAndRootEdges: `not-locked` is named by requests and
// has no entry, so it is not a package this lock resolved; inventing the node
// would assert a dependency the project does not install. The root project is
// excluded from the inventory, so an edge to it would name a node that is not
// there either.
func TestUvLockDropsUnresolvedAndRootEdges(t *testing.T) {
	f, err := os.Open("testdata/simple.lock")
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "uv.lock")
	require.NoError(t, err)
	pkgs := bom.Transitive()

	for _, ref := range pkgs.Find("requests").DependsOn {
		assert.NotContains(t, ref, "not-locked", "an unresolved name must not become an edge")
	}
	assert.Nil(t, pkgs.Find("not-locked"), "and must not become a package")
	for _, p := range pkgs {
		for _, ref := range p.DependsOn {
			assert.NotContains(t, ref, "my-project", "no edge may point at the root project")
		}
	}
}
