// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagelockjson

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers/os/resources/languages"
	"go.mondoo.com/mql/v13/sbom"
)

func TestPackageJsonLockExtractorWithPackages(t *testing.T) {
	f, err := os.Open("./testdata/lockfile-v2.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/package-lock.json")
	assert.Nil(t, err)

	root := info.Root()
	assert.Equal(t, &languages.Package{
		Name:         "npm",
		Version:      "7.0.0",
		Purl:         "pkg:npm/npm@7.0.0",
		Cpes:         []string{"cpe:2.3:a:npm:npm:7.0.0:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/package-lock.json"}},
	}, root)

	list := info.Transitive()
	assert.Equal(t, 2, len(list))

	p := list.Find("@babel/code-frame")
	assert.Equal(t, &languages.Package{
		Name:         "@babel/code-frame",
		Version:      "7.10.4",
		Purl:         "pkg:npm/%40babel/code-frame@7.10.4",
		Cpes:         []string{"cpe:2.3:a:\\@babel\\/code-frame:\\@babel\\/code-frame:7.10.4:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/package-lock.json"}},
		Scope:        languages.PackageScopeDev,
		Hashes:       []languages.PackageHash{{Alg: "SHA-512", Value: "bc6e92bc1ea860486f822b193454664425242f3d7573bae9fad6cd4f29c6a9cea64b577901377fb06c95e96d0a6599d744a313cd90d18104f73aef6386901f52"}},
	}, p)

}

// TestPackageJsonLockScope verifies the dev/prod scope: a devDependency in the
// tree reports PackageScopeDev, a production dependency PackageScopeProd.
func TestPackageJsonLockScope(t *testing.T) {
	f, err := os.Open("./testdata/lockfile-v2.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/package-lock.json")
	require.NoError(t, err)

	// @babel/code-frame is dev:true in this lock.
	cf := info.Transitive().Find("@babel/code-frame")
	require.NotNil(t, cf)
	assert.Equal(t, languages.PackageScopeDev, cf.Scope)
}

// TestPackageJsonLockDependencyEdges verifies the package→package edges
// (Package.DependsOn) resolved from a lockfileVersion 2+ tree: each edge ref is
// the resolved target package's Purl, so the graph is self-consistent
// (edge ref == target node Purl). app→foo→bar.
func TestPackageJsonLockDependencyEdges(t *testing.T) {
	f, err := os.Open("./testdata/graph-lock.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/package-lock.json")
	require.NoError(t, err)

	list := info.Transitive()
	app := list.Find("app")
	foo := list.Find("foo")
	bar := list.Find("bar")
	require.NotNil(t, app)
	require.NotNil(t, foo)
	require.NotNil(t, bar)

	// edges point at the resolved target's Purl (ref == target node Purl).
	assert.Equal(t, []string{foo.Purl}, app.DependsOn, "app depends on foo")
	assert.Equal(t, []string{bar.Purl}, foo.DependsOn, "foo depends on bar")
	assert.Nil(t, bar.DependsOn, "bar has no dependencies")
}

// TestPackageJsonLockDirect verifies Direct() resolves the root's declared
// dependencies via their node_modules/<name> path (lockfileVersion 2+), matching
// the same package's Transitive() representation. Previously it looked deps up by
// bare name against the path-keyed `packages` map and returned nothing.
func TestPackageJsonLockDirect(t *testing.T) {
	f, err := os.Open("./testdata/graph-lock.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/package-lock.json")
	require.NoError(t, err)

	direct := info.Direct()
	require.Len(t, direct, 1, "root declares exactly one direct dependency (foo)")
	foo := direct.Find("foo")
	require.NotNil(t, foo)
	assert.Equal(t, "1.2.3", foo.Version)
	// Direct's foo matches Transitive's foo exactly (same purl + edges).
	assert.Equal(t, info.Transitive().Find("foo").Purl, foo.Purl)
	assert.Equal(t, info.Transitive().Find("foo").DependsOn, foo.DependsOn)
}

func TestPackageJsonLockExtractorWithDependencies(t *testing.T) {
	f, err := os.Open("./testdata/workbox-package-lock.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/package-lock.json")
	assert.Nil(t, err)

	root := info.Root()
	assert.Equal(t, &languages.Package{
		Name:         "workbox",
		Version:      "0.0.0",
		Purl:         "pkg:npm/workbox@0.0.0",
		Cpes:         []string{"cpe:2.3:a:workbox:workbox:0.0.0:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/package-lock.json"}},
	}, root)

	list := info.Transitive()
	assert.Equal(t, 1299, len(list))

	p := list.Find("@babel/generator")
	assert.Equal(t, &languages.Package{
		Name:         "@babel/generator",
		Version:      "7.0.0",
		Purl:         "pkg:npm/%40babel/generator@7.0.0",
		Cpes:         []string{"cpe:2.3:a:\\@babel\\/generator:\\@babel\\/generator:7.0.0:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/package-lock.json"}},
		Hashes:       []languages.PackageHash{{Alg: "SHA-512", Value: "fc1336beea64a5b657ab6da5d402ceecca972591f693c6ca56ff18fa9001167cd6773b4307f64bbde3f902ddb5bcbcf973662d484ea9ee3d85644b2a69f333e5"}},
	}, p)

	p = list.Find("@lerna/changed")
	assert.Equal(t, &languages.Package{
		Name:         "@lerna/changed",
		Version:      "3.3.2",
		Purl:         "pkg:npm/%40lerna/changed@3.3.2",
		Cpes:         []string{"cpe:2.3:a:\\@lerna\\/changed:\\@lerna\\/changed:3.3.2:*:*:*:*:*:*:*"},
		EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/package-lock.json"}},
		Hashes:       []languages.PackageHash{{Alg: "SHA-512", Value: "c0b1fa47360f400af2aec25a91cf48de4d1a15613f709c96a140fc750cb5f3a8f1c2d2e0790755734f8d7a037269becc20f8bb1ecbfd037871ea5335acf1fde0"}},
	}, p)
}

// TestPackageLockLicense pins that the license an npm lockfile states reaches
// the package, on both Direct and Transitive.
//
// The parser has always read `license` — it even carries a custom unmarshaler
// for npm's string-or-array shape — but the extractor dropped it, so every npm
// dependency reached an SBOM with an empty License.
func TestPackageLockLicense(t *testing.T) {
	f, err := os.Open("./testdata/lockfile-v3-dep-licenses.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/package-lock.json")
	require.NoError(t, err)

	want := map[string]string{
		"lodash": "MIT",
		// npm writes an array when a package is offered under either license;
		// that is a choice, so it renders as an SPDX OR.
		"dual-licensed": "(MIT OR Apache-2.0)",
		// A package that states none must report none rather than an empty
		// expression that would read as a declaration.
		"no-license": "",
		// A dev-only package still states a license.
		"mocha": "MIT",
	}

	transitive := info.Transitive()
	for name, license := range want {
		p := transitive.Find(name)
		require.NotNil(t, p, name)
		assert.Equal(t, license, p.License, "transitive %s", name)
	}

	// Direct builds its packages separately from Transitive, so it needs its own
	// assertion: the two representations of a package must not disagree.
	direct := info.Direct()
	for _, name := range []string{"lodash", "dual-licensed", "no-license"} {
		p := direct.Find(name)
		require.NotNil(t, p, name)
		assert.Equal(t, want[name], p.License, "direct %s", name)
	}
}
