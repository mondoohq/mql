// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versioncatalog

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

func parseCatalog(t *testing.T) languages.Bom {
	t.Helper()
	f, err := os.Open("./testdata/libs.versions.toml")
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, "gradle/libs.versions.toml")
	require.NoError(t, err)
	return bom
}

func TestVersionCatalogSpellings(t *testing.T) {
	deps := parseCatalog(t).Transitive()
	assert.Nil(t, parseCatalog(t).Root())

	p := deps.Find("com.squareup.okio:okio")
	require.NotNil(t, p, "module + version.ref")
	assert.Equal(t, "3.9.0", p.Version)
	assert.Equal(t, "pkg:maven/com.squareup.okio/okio@3.9.0", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "gradle/libs.versions.toml"}}, p.EvidenceList)

	p = deps.Find("com.willowtreeapps.assertk:assertk")
	require.NotNil(t, p, "module + literal version")
	assert.Equal(t, "0.28.1", p.Version)

	p = deps.Find("com.google.guava:guava")
	require.NotNil(t, p, "separate group and name")
	assert.Equal(t, "33.7.1-jre", p.Version)

	p = deps.Find("org.bouncycastle:bc-jdk15to18-bom")
	require.NotNil(t, p, "plain string shorthand")
	assert.Equal(t, "1.85.2", p.Version)

	p = deps.Find("org.junit.jupiter:junit-jupiter")
	require.NotNil(t, p, "rich constraint { require = } behind a ref")
	assert.Equal(t, "5.10.0", p.Version)

	assert.Equal(t, "2.5.0", deps.Find("com.example:strict").Version, "{ strictly = } names one release")

	// A version supplied by a BOM is unknown here. The artifact is still real
	// and still reported; nothing is claimed about which version it is.
	p = deps.Find("org.bouncycastle:bcprov-jdk15to18")
	require.NotNil(t, p)
	assert.Empty(t, p.Version)
}

func TestVersionCatalogRefusesToInventVersions(t *testing.T) {
	deps := parseCatalog(t).Transitive()

	// A range names a SET of releases. Recording one as a version produces a
	// purl matching no release, and reads downstream as a definite claim about
	// what is installed.
	for _, tc := range []struct{ name, why string }{
		{"com.example:dynamic", "1.+ is a dynamic version"},
		{"com.example:ranged", "[1.0, 2.0[ is a range"},
		{"com.example:dangling", "version.ref points at no [versions] entry"},
	} {
		p := deps.Find(tc.name)
		require.NotNil(t, p, "%s: the artifact is real and must still be inventoried", tc.why)
		assert.Empty(t, p.Version, "%s: version must be unknown, not invented", tc.why)
	}
}

func TestVersionCatalogReadsLibrariesOnly(t *testing.T) {
	deps := parseCatalog(t).Transitive()

	// [plugins] names a Gradle plugin id, which is not a Maven coordinate;
	// [bundles] lists aliases already covered by [libraries].
	for _, p := range deps {
		assert.NotEqual(t, "com.android.application", p.Name, "a plugin id must not be read as a coordinate")
		assert.NotEqual(t, "testing", p.Name, "a bundle must not be read as a coordinate")
	}
	assert.Equal(t, 10, len(deps), "every [libraries] entry, and nothing else")
}

func TestVersionCatalogDirectIsEveryLibrary(t *testing.T) {
	bom := parseCatalog(t)
	// A catalog entry is a coordinate the project wrote down for itself.
	assert.Equal(t, len(bom.Transitive()), len(bom.Direct()))
}
