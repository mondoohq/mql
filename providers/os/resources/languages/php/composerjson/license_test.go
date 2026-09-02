// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package composerjson

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func rootOf(t *testing.T, fixture string) *languages.Package {
	t.Helper()
	f, err := os.Open("./testdata/" + fixture)
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "composer.json")
	require.NoError(t, err)
	root := bom.Root()
	require.NotNil(t, root)
	return root
}

// The common form: one license, passed through as the manifest wrote it and
// without acquiring parentheses it did not have.
func TestComposerJsonReadsASingleLicense(t *testing.T) {
	assert.Equal(t, "MIT", rootOf(t, "single-license.composer.json").License)
}

// Composer defines the array form as a DISJUNCTIVE license — the package is
// offered under any one of them and the consumer chooses — which is SPDX's OR.
// composer.lock renders the same field the same way, so a project and its
// lockfile now answer this identically.
func TestComposerJsonReadsADisjunctiveLicense(t *testing.T) {
	assert.Equal(t, "(LGPL-2.1-only OR GPL-3.0-or-later)",
		rootOf(t, "disjunctive-license.composer.json").License)
}

// A shape Composer does not define must not sink the manifest. The license is
// unread — which is the honest answer — and the inventory still parses.
func TestComposerJsonSurvivesALicenseItCannotRead(t *testing.T) {
	root := rootOf(t, "odd-license.composer.json")
	assert.Empty(t, root.License)
	assert.Equal(t, "myvendor/odd", root.Name, "the rest of the manifest must still parse")
}

// A manifest that declares nothing reports nothing, distinct from one whose
// license this could not render.
func TestComposerJsonWithNoLicenseReportsNone(t *testing.T) {
	assert.Empty(t, rootOf(t, "simple.composer.json").License)
}
