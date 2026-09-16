// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package conanlock

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers/os/resources/languages"
)

func parseFixture(t *testing.T, path string) languages.Bom {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, path)
	require.NoError(t, err)
	return bom
}

func TestParseV1(t *testing.T) {
	bom := parseFixture(t, "testdata/v1.json")

	assert.Nil(t, bom.Root())
	// A v1 graph lock encodes real edges that this parser does not yet walk, so
	// it reports everything as transitive rather than guessing a direct set.
	assert.Nil(t, bom.Direct())

	pkgs := bom.Transitive()
	assert.Len(t, pkgs, 5) // myproject skipped (has path)

	boost := pkgs.Find("boost")
	require.NotNil(t, boost)
	assert.Equal(t, "1.84.0", boost.Version)
	// The recipe revision is parsed and deliberately left out of the purl: no
	// advisory states one, so carrying it could only turn a match into a miss.
	assert.Equal(t, "pkg:conan/boost@1.84.0", boost.Purl)
	assert.Equal(t, languages.PackageScopeProd, boost.Scope)

	// A node in the build context is build tooling, the v1 spelling of what a
	// v2 lockfile puts in build_requires.
	ninja := pkgs.Find("ninja")
	require.NotNil(t, ninja)
	assert.Equal(t, languages.PackageScopeDev, ninja.Scope,
		"a build-context node is not linked into the artifact")

	// A reference from a user and channel is NOT the ConanCenter package of the
	// same name; the purl has to say so or a private package inherits the
	// public one's advisories.
	mylib := pkgs.Find("mylib")
	require.NotNil(t, mylib)
	assert.Equal(t, "pkg:conan/acme/mylib@2.0?channel=stable", mylib.Purl)
}

func TestParseV1IsDeterministic(t *testing.T) {
	// Nodes are a JSON object; ranging the map would reorder the SBOM between
	// runs of the same scan.
	first := names(parseFixture(t, "testdata/v1.json").Transitive())
	for i := 0; i < 20; i++ {
		assert.Equal(t, first, names(parseFixture(t, "testdata/v1.json").Transitive()))
	}
}

func TestParseV2(t *testing.T) {
	bom := parseFixture(t, "testdata/v2.json")

	// A v2 lockfile's `requires` is the consumer's own requirement list, so its
	// packages are direct. Reporting them as transitive meant `deps list
	// --scope direct` returned nothing and the direct-unused demotion could
	// never fire.
	assert.Nil(t, bom.Transitive())
	pkgs := bom.Direct()
	require.NotNil(t, pkgs)

	boost := pkgs.Find("boost")
	require.NotNil(t, boost)
	assert.Equal(t, "1.84.0", boost.Version)
	assert.Equal(t, "pkg:conan/boost@1.84.0", boost.Purl)
	assert.Equal(t, languages.PackageScopeProd, boost.Scope, "requires are production")

	// build_requires, python_requires and config_requires are build-time
	// tooling → dev scope.
	for _, name := range []string{"cmake", "conan-tools", "myconf"} {
		pkg := pkgs.Find(name)
		require.NotNil(t, pkg, "%s missing", name)
		assert.Equal(t, languages.PackageScopeDev, pkg.Scope, "%s is build tooling", name)
	}

	mylib := pkgs.Find("mylib")
	require.NotNil(t, mylib)
	assert.Equal(t, "pkg:conan/acme/mylib@2.0?channel=stable", mylib.Purl)
}

// TestConfigRequiresIsRead pins the field that was absent from the struct, so a
// Conan 2.4+ lockfile's config packages were dropped entirely rather than
// scoped out — --include-dev did not bring them back either.
func TestConfigRequiresIsRead(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(
		`{"version":"0.5","config_requires":["myconf/1.0"]}`), "conan.lock")
	require.NoError(t, err)
	pkgs := bom.Direct()
	require.Len(t, pkgs, 1)
	assert.Equal(t, "myconf", pkgs[0].Name)
	assert.Equal(t, languages.PackageScopeDev, pkgs[0].Scope)
}

// TestDirectAndTransitiveDoNotOverlap guards the invariant a consumer relies on
// when it concatenates the two: a package in both is emitted twice.
func TestDirectAndTransitiveDoNotOverlap(t *testing.T) {
	for _, fixture := range []string{"testdata/v1.json", "testdata/v2.json"} {
		bom := parseFixture(t, fixture)
		direct := map[string]bool{}
		for _, p := range bom.Direct() {
			direct[p.Purl] = true
		}
		for _, p := range bom.Transitive() {
			assert.False(t, direct[p.Purl], "%s: %s is in both sets", fixture, p.Purl)
		}
	}
}

func TestName(t *testing.T) {
	assert.Equal(t, "conanlock", (&Extractor{}).Name())
}

func names(pkgs languages.Packages) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name)
	}
	return out
}

// TestIsV2VersionParsing pins the format detection against a dotted version.
// A lockfile version is not a number: "0.5.1" failed ParseFloat, and the error
// path chose the V1 parser for a v2 file — which reports nothing at all, since
// a v2 lockfile has no graph_lock to walk.
func TestIsV2VersionParsing(t *testing.T) {
	tests := map[string]bool{
		"0.3": false, "0.4": false, // v1 graph_lock formats
		"0.5": true, "0.6": true, // v2
		"0.5.1": true, "0.10": true, "1.0": true, "1.2.3": true,
		"": false, "abc": false, "0": false,
	}
	for version, wantV2 := range tests {
		l := &conanLock{Version: version}
		assert.Equal(t, wantV2, l.isV2(), "version %q", version)
	}
}

// TestV2LockWithPatchVersionStillParses is the consequence the unit above
// guards, end to end: a v2 lockfile at a patch version reported no packages.
func TestV2LockWithPatchVersionStillParses(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(
		`{"version":"0.5.1","requires":["zlib/1.3.1"]}`), "conan.lock")
	require.NoError(t, err)
	pkgs := bom.Direct()
	require.Len(t, pkgs, 1)
	assert.Equal(t, "zlib", pkgs[0].Name)
}
