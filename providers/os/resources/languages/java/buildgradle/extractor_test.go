// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package buildgradle

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

func parseFile(t *testing.T, path, name string) languages.Bom {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, name)
	require.NoError(t, err)
	return bom
}

func TestBuildGradleGroovy(t *testing.T) {
	bom := parseFile(t, "./testdata/simple.build.gradle", "path/to/build.gradle")

	// A build script does not name the project it builds.
	assert.Nil(t, bom.Root())

	deps := bom.Transitive()

	p := deps.Find("com.fasterxml.jackson.core:jackson-databind")
	require.NotNil(t, p)
	assert.Equal(t, "2.9.10.1", p.Version, "version from an ext block property")
	assert.Equal(t, "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1", p.Purl)
	assert.Equal(t, languages.PackageScopeProd, p.Scope)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/build.gradle"}}, p.EvidenceList)

	p = deps.Find("org.apache.logging.log4j:log4j-core")
	require.NotNil(t, p)
	assert.Equal(t, "2.14.1", p.Version, "version from a `def` interpolated as $log4jVersion")

	// The property is declared below the dependencies block; collection is
	// whole-file so declaration order does not decide.
	p = deps.Find("org.yaml:snakeyaml")
	require.NotNil(t, p)
	assert.Equal(t, "1.29", p.Version, "version from an ext.x property declared after use")

	p = deps.Find("com.google.guava:guava")
	require.NotNil(t, p)
	assert.Equal(t, "24.1.1-jre", p.Version, "map notation")

	p = deps.Find("org.apache.httpcomponents:httpclient")
	require.NotNil(t, p)
	assert.Equal(t, "4.5.13", p.Version)

	// A version managed by a BOM is unknown here, not absent: the artifact is
	// reported, with no version claimed for it.
	p = deps.Find("org.springframework.boot:spring-boot-starter-web")
	require.NotNil(t, p)
	assert.Empty(t, p.Version)
	assert.Equal(t, "pkg:maven/org.springframework.boot/spring-boot-starter-web", p.Purl)

	assert.Equal(t, languages.PackageScopeDev, deps.Find("junit:junit").Scope)
	assert.Equal(t, languages.PackageScopeDev, deps.Find("org.mockito:mockito-core").Scope)

	// Declared in buildscript{}: build tooling, never shipped.
	assert.Equal(t, languages.PackageScopeDev, deps.Find("org.springframework.boot:spring-boot-gradle-plugin").Scope)

	// Declared as both compileOnly and annotationProcessor. It is one package,
	// and the shipping configuration decides the scope regardless of which line
	// came first.
	p = deps.Find("org.projectlombok:lombok")
	require.NotNil(t, p)
	assert.Equal(t, languages.PackageScopeProd, p.Scope)
	assert.Equal(t, 1, countNamed(deps, "org.projectlombok:lombok"), "declared twice, reported once")
}

func TestBuildGradleOmitsWhatItCannotRead(t *testing.T) {
	deps := parseFile(t, "./testdata/simple.build.gradle", "build.gradle").Transitive()

	// A coordinate that is not a Maven artifact must not become a package: a
	// fabricated entry is worse than a missing one, because it reports a
	// dependency the project does not have.
	for _, name := range []string{
		"commons-logging:commons-logging",   // an exclude inside a trailing closure
		"com.fasterxml.jackson:jackson-bom", // a platform(): a constraint, ships no code
	} {
		assert.Nil(t, deps.Find(name), "%s must not be reported", name)
	}

	for _, p := range deps {
		assert.NotContains(t, p.Name, "$", "an unresolved interpolation must never reach a package name")
		assert.NotContains(t, p.Version, "$", "an unresolved interpolation must never reach a version")
		assert.NotContains(t, p.Name, "/", "a file path must never be read as a coordinate")
		require.Equal(t, 2, len(strings.Split(p.Name, ":")), "a name is exactly group:artifact")
	}
}

func TestBuildGradleKotlinDSL(t *testing.T) {
	deps := parseFile(t, "./testdata/kotlin.build.gradle.kts", "build.gradle.kts").Transitive()

	p := deps.Find("com.fasterxml.jackson.core:jackson-databind")
	require.NotNil(t, p)
	assert.Equal(t, "2.9.10.1", p.Version, "version from a `val` interpolated as $jacksonVersion")

	p = deps.Find("com.google.guava:guava")
	require.NotNil(t, p)
	assert.Equal(t, "24.1.1-jre", p.Version, "Kotlin named-argument map notation")

	assert.Equal(t, "1.29", deps.Find("org.yaml:snakeyaml").Version)
	assert.Equal(t, languages.PackageScopeDev, deps.Find("junit:junit").Scope)

	// A version catalog accessor names no coordinate in this file. Resolving it
	// needs libs.versions.toml, so it is omitted rather than guessed at.
	assert.Equal(t, 4, len(deps))
}

func TestDirectIsEveryDeclaration(t *testing.T) {
	bom := parseFile(t, "./testdata/kotlin.build.gradle.kts", "build.gradle.kts")

	// Everything a build script declares is direct — the script is where the
	// project asked for it. Dev scope is the orthogonal axis and does not
	// remove a dependency from the direct set.
	assert.Equal(t, len(bom.Transitive()), len(bom.Direct()))
	assert.NotNil(t, bom.Direct().Find("junit:junit"))
}

func TestStripComment(t *testing.T) {
	assert.Equal(t, "implementation 'a:b:1' ", stripComment("implementation 'a:b:1' // pinned"))
	// A URL inside a string literal is not a comment.
	assert.Equal(t, "url 'https://repo.example.com/x'", stripComment("url 'https://repo.example.com/x'"))
	assert.Equal(t, "", stripComment("// all comment"))
}

func TestIsDevConfiguration(t *testing.T) {
	assert.True(t, isDevConfiguration("testImplementation", false))
	assert.True(t, isDevConfiguration("androidTestImplementation", false))
	assert.True(t, isDevConfiguration("annotationProcessor", false))
	assert.True(t, isDevConfiguration("classpath", false))
	// Anything inside buildscript{} is build tooling whatever it is called.
	assert.True(t, isDevConfiguration("implementation", true))

	assert.False(t, isDevConfiguration("implementation", false))
	assert.False(t, isDevConfiguration("api", false))
	// compileOnly is on the compile classpath and NOT the runtime one, so it
	// often does not ship. It counts as prod anyway: whether the artifact
	// reaches production is a packaging question this parser cannot answer, and
	// scoping a shipped dependency as dev hides a real CVE, where the reverse
	// merely reports one that may not apply.
	assert.False(t, isDevConfiguration("compileOnly", false))
	assert.False(t, isDevConfiguration("runtimeOnly", false))
}

func TestResolveInterp(t *testing.T) {
	vars := map[string]string{"v": "1.2.3"}
	assert.Equal(t, "1.2.3", resolveInterp("$v", vars))
	assert.Equal(t, "1.2.3", resolveInterp("${v}", vars))
	assert.Equal(t, "1.2.3", resolveInterp("${project.ext.v}", vars))
	assert.Equal(t, "4.5.6", resolveInterp("4.5.6", vars))
	// An unresolvable reference is an unknown version, never a literal.
	assert.Equal(t, "", resolveInterp("$missing", vars))
	assert.Equal(t, "", resolveInterp("", vars))
}

func countNamed(deps languages.Packages, name string) int {
	n := 0
	for _, p := range deps {
		if p.Name == name {
			n++
		}
	}
	return n
}

// Brace depth decides whether a declaration sits in the dependencies block or
// inside a trailing configuration closure, so a brace inside a string literal
// used to move every later declaration a level deeper and drop it — a
// dependency silently missing, which is the failure this extractor removes.
func TestBraceInsideAStringDoesNotHideDependencies(t *testing.T) {
	for _, c := range []struct{ name, script string }{
		{"unbalanced open brace in a string", `
dependencies {
    def placeholder = "{"
    implementation 'com.example:kept:1.0'
}
`},
		{"unbalanced close brace in a string", `
dependencies {
    def placeholder = "}"
    implementation 'com.example:kept:1.0'
}
`},
		{"brace in a string before the block", `
def marker = "{"
dependencies {
    implementation 'com.example:kept:1.0'
}
`},
	} {
		t.Run(c.name, func(t *testing.T) {
			bom, err := (&Extractor{}).Parse(strings.NewReader(c.script), "build.gradle")
			require.NoError(t, err)
			require.NotNil(t, bom.Direct().Find("com.example:kept"))
		})
	}

	// And the closure it protects still works: an exclude is a dependency being
	// removed, not one being added.
	t.Run("an exclude closure is still not a declaration", func(t *testing.T) {
		bom, err := (&Extractor{}).Parse(strings.NewReader(`
dependencies {
    implementation('com.example:kept:1.0') {
        exclude group: 'com.evil', module: 'badlib'
    }
}
`), "build.gradle")
		require.NoError(t, err)
		assert.NotNil(t, bom.Direct().Find("com.example:kept"))
		assert.Nil(t, bom.Direct().Find("com.evil:badlib"), "an exclude removes a dependency")
	})
}

// A dynamic version names a set of releases, so it is not recorded as one: the
// artifact is inventoried with its version unknown, the same treatment the
// version catalog gives it.
func TestDynamicVersionsAreNotRecordedAsVersions(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(`
dependencies {
    implementation 'com.example:pinned:1.2.3'
    implementation 'com.example:dynamic:1.+'
    implementation 'com.example:ranged:[1.0, 2.0['
    implementation 'com.example:newest:latest.release'
}
`), "build.gradle")
	require.NoError(t, err)

	assert.Equal(t, "1.2.3", bom.Direct().Find("com.example:pinned").Version)
	for _, name := range []string{"com.example:dynamic", "com.example:ranged", "com.example:newest"} {
		p := bom.Direct().Find(name)
		require.NotNil(t, p, "%s is still inventoried", name)
		assert.Empty(t, p.Version, "%s names a set of releases, not a release", name)
	}
}
