// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vcpkg

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/vcpkg.json")
	require.NoError(t, err)
	defer f.Close()

	e := &Extractor{}
	bom, err := e.Parse(f, "testdata/vcpkg.json")
	require.NoError(t, err)

	// The manifest's own port is the root project, not a dependency.
	root := bom.Root()
	require.NotNil(t, root)
	assert.Equal(t, "my-app", root.Name)
	assert.Equal(t, "1.2.0", root.Version)
	assert.Equal(t, "pkg:vcpkg/my-app@1.2.0", root.Purl)

	assert.Nil(t, bom.Transitive())

	deps := bom.Direct()
	// fmt (deduped from its two occurrences), zlib, boost-system, vcpkg-cmake,
	// plus catch2 and openssl from the two features.
	assert.Len(t, deps, 6)

	fmtPkg := deps.Find("fmt")
	require.NotNil(t, fmtPkg)
	// No override → no manifest-stated version.
	assert.Equal(t, "", fmtPkg.Version)
	assert.Equal(t, "pkg:vcpkg/fmt", fmtPkg.Purl)

	zlib := deps.Find("zlib")
	require.NotNil(t, zlib)
	// Version pinned by an override.
	assert.Equal(t, "1.3.1", zlib.Version)
	assert.Equal(t, "pkg:vcpkg/zlib@1.3.1", zlib.Purl)

	// Object-form dependency resolves to its name. Its `version>=` is a FLOOR,
	// not a pin: vcpkg resolves through the registry baseline, routinely to
	// something higher, so promoting it to the version would name a release the
	// project does not build against. It rides as a qualifier instead.
	boost := deps.Find("boost-system")
	require.NotNil(t, boost)
	assert.Empty(t, boost.Version)
	assert.Equal(t, "pkg:vcpkg/boost-system?version_min=1.84.0", boost.Purl)

	// A host dependency is a build-time tool, vcpkg's equivalent of a Conan
	// tool_requires — not code linked into the artifact.
	hostDep := deps.Find("vcpkg-cmake")
	require.NotNil(t, hostDep)
	assert.Equal(t, languages.PackageScopeDev, hostDep.Scope)
	assert.Equal(t, languages.PackageScopeProd, fmtPkg.Scope)

	// Feature dependencies are real dependencies of any build that selects the
	// feature, and this file cannot know which builds do. Omitting them hides a
	// dependency; including one an unselected build does not use costs an
	// unreachable component. Only the first loses a vulnerability.
	catch2 := deps.Find("catch2")
	require.NotNil(t, catch2, "a feature's dependencies are still dependencies")
	openssl := deps.Find("openssl")
	require.NotNil(t, openssl)
	assert.Equal(t, "pkg:vcpkg/openssl?version_min=3.0.8", openssl.Purl)
}

// TestFeatureOrderIsDeterministic guards against ranging the features map,
// which would reorder the SBOM between runs of the same scan.
func TestFeatureOrderIsDeterministic(t *testing.T) {
	read := func() []string {
		f, err := os.Open("testdata/vcpkg.json")
		require.NoError(t, err)
		defer f.Close()
		bom, err := (&Extractor{}).Parse(f, "testdata/vcpkg.json")
		require.NoError(t, err)
		var out []string
		for _, p := range bom.Direct() {
			out = append(out, p.Name)
		}
		return out
	}
	first := read()
	for i := 0; i < 20; i++ {
		assert.Equal(t, first, read())
	}
}

// TestOverrideBeatsFloor pins that an exact pin wins over a floor rather than
// carrying both — a package with a version has no use for a minimum.
func TestOverrideBeatsFloor(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(`{
	  "name":"app",
	  "dependencies":[{"name":"zlib","version>=":"1.2.0"}],
	  "overrides":[{"name":"zlib","version":"1.3.1"}]
	}`), "vcpkg.json")
	require.NoError(t, err)
	zlib := bom.Direct().Find("zlib")
	require.NotNil(t, zlib)
	assert.Equal(t, "pkg:vcpkg/zlib@1.3.1", zlib.Purl)
}

func TestName(t *testing.T) {
	e := &Extractor{}
	assert.Equal(t, "vcpkg", e.Name())
}
