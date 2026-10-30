// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomxml

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

func TestPomXmlExtractorSimple(t *testing.T) {
	f, err := os.Open("./testdata/simple.pom.xml")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/pom.xml")
	require.NoError(t, err)

	// Root project
	root := info.Root()
	require.NotNil(t, root)
	assert.Equal(t, "com.example:myapp", root.Name)
	assert.Equal(t, "1.0.0", root.Version)
	assert.Equal(t, "pkg:maven/com.example/myapp@1.0.0", root.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/pom.xml"}}, root.EvidenceList)

	// Direct deps (excludes test and provided)
	direct := info.Direct()
	assert.Equal(t, 2, len(direct))

	p := direct.Find("org.apache.commons:commons-lang3")
	require.NotNil(t, p)
	assert.Equal(t, "3.12.0", p.Version)
	assert.Equal(t, "pkg:maven/org.apache.commons/commons-lang3@3.12.0", p.Purl)

	p = direct.Find("com.google.guava:guava")
	require.NotNil(t, p)
	assert.Equal(t, "31.1-jre", p.Version)

	// Transitive includes all 4 deps (including test and provided)
	transitive := info.Transitive()
	assert.Equal(t, 4, len(transitive))

	p = transitive.Find("junit:junit")
	require.NotNil(t, p)
	assert.Equal(t, "4.13.2", p.Version)

	p = transitive.Find("javax.servlet:javax.servlet-api")
	require.NotNil(t, p)
	assert.Equal(t, "4.0.1", p.Version)
}

// A version written as ${jackson.version} is how a Maven project keeps a family
// of artifacts on one version, and it is extremely common. Before properties
// were resolved, the dependency's version was the literal property reference —
// which produces a purl that matches no package registry and no advisory, so
// the dependency was silently exempt from vulnerability correlation and from
// license lookup alike.
func TestPomXmlResolvesPropertyVersions(t *testing.T) {
	f, err := os.Open("./testdata/properties.pom.xml")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "pom.xml")
	require.NoError(t, err)

	byName := map[string]*languages.Package{}
	for _, p := range info.Transitive() {
		byName[p.Name] = p
	}

	t.Run("a declared property is substituted", func(t *testing.T) {
		p := byName["org.springframework:spring-core"]
		require.NotNil(t, p)
		assert.Equal(t, "5.3.18", p.Version)
		assert.Equal(t, "pkg:maven/org.springframework/spring-core@5.3.18", p.Purl)
	})

	t.Run("a property whose value is another property resolves through", func(t *testing.T) {
		p := byName["com.fasterxml.jackson.core:jackson-databind"]
		require.NotNil(t, p)
		assert.Equal(t, "2.13.0", p.Version)
		assert.Equal(t, "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", p.Purl)
	})

	t.Run("project.version is a built-in", func(t *testing.T) {
		p := byName["com.example:myapp-core"]
		require.NotNil(t, p)
		assert.Equal(t, "2.5.0", p.Version)
	})

	t.Run("dependencyManagement supplies an omitted version", func(t *testing.T) {
		p := byName["com.google.guava:guava"]
		require.NotNil(t, p)
		assert.Equal(t, "31.1-jre", p.Version)
		assert.Equal(t, "pkg:maven/com.google.guava/guava@31.1-jre", p.Purl)
	})

	// An unresolvable reference stays as written. Substituting a guess would
	// report the dependency at some other version's identity, matching that
	// version's advisories and that version's license; leaving the reference
	// intact keeps the gap visible to whatever reads it.
	t.Run("an undeclared property is not guessed at", func(t *testing.T) {
		p := byName["org.example:mystery"]
		require.NotNil(t, p)
		assert.Equal(t, "${undeclared.version}", p.Version)
	})
}

// A property may refer to itself, directly or through a cycle. Resolution must
// terminate rather than spin, and must not invent a value.
func TestPomXmlPropertyCycleTerminates(t *testing.T) {
	pom := `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>g</groupId><artifactId>a</artifactId><version>1.0</version>
  <properties><a.version>${b.version}</a.version><b.version>${a.version}</b.version></properties>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>dep</artifactId><version>${a.version}</version></dependency>
  </dependencies>
</project>`
	done := make(chan *languages.Package, 1)
	go func() {
		info, err := (&Extractor{}).Parse(strings.NewReader(pom), "pom.xml")
		if err != nil {
			done <- nil
			return
		}
		for _, p := range info.Transitive() {
			if p.Name == "g:dep" {
				done <- p
				return
			}
		}
		done <- nil
	}()
	select {
	case p := <-done:
		require.NotNil(t, p)
		// Whatever it settles on, it must still look unresolved rather than
		// having been given a fabricated version.
		assert.Contains(t, p.Version, "${")
	case <-time.After(10 * time.Second):
		t.Fatal("property resolution did not terminate on a cyclic declaration")
	}
}

// parsePom is a small helper for the POMs below, which are written inline
// because each one exists to hold a single shape.
func parsePom(t *testing.T, pom string) *pomProject {
	t.Helper()
	info, err := (&Extractor{}).Parse(strings.NewReader(pom), "pom.xml")
	require.NoError(t, err)
	p, ok := info.(*pomProject)
	require.True(t, ok, "Parse should return a *pomProject")
	return p
}

func packagesByName(pkgs languages.Packages) map[string]*languages.Package {
	out := map[string]*languages.Package{}
	for _, p := range pkgs {
		out[p.Name] = p
	}
	return out
}

// A <dependency> and the <dependencyManagement> entry that versions it need not
// spell their coordinates the same way: writing ${project.groupId} in one and
// the literal in the other is ordinary, and so is the reverse. Comparing them as
// written matches only by coincidence, and a miss is silent — the dependency
// comes out with no version at all, which is the outcome resolving versions was
// meant to prevent.
func TestPomXmlManagedVersionMatchesAcrossPropertyReferences(t *testing.T) {
	t.Run("the dependency uses a property, the management entry is literal", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>2.5.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.example</groupId><artifactId>myapp-core</artifactId><version>2.5.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>${project.groupId}</groupId><artifactId>myapp-core</artifactId></dependency>
  </dependencies>
</project>`)

		got := packagesByName(p.Transitive())["com.example:myapp-core"]
		require.NotNil(t, got)
		assert.Equal(t, "2.5.0", got.Version)
		assert.Equal(t, "pkg:maven/com.example/myapp-core@2.5.0", got.Purl)
	})

	t.Run("the management entry uses a property, the dependency is literal", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>2.5.0</version>
  <properties><guava.groupId>com.google.guava</guava.groupId></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>${guava.groupId}</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId></dependency>
  </dependencies>
</project>`)

		got := packagesByName(p.Transitive())["com.google.guava:guava"]
		require.NotNil(t, got)
		assert.Equal(t, "31.1-jre", got.Version)
		assert.Equal(t, "pkg:maven/com.google.guava/guava@31.1-jre", got.Purl)
	})
}

// Maven applies a managed scope exactly as it applies a managed version, so the
// two have to be read together. A dependency omitting both is a test dependency
// at the managed version; reading only the version promotes it into the
// production set with a real, matchable purl, and it arrives in an SBOM as
// something the application ships.
func TestPomXmlManagedScopeKeepsTestDependenciesOutOfDirect(t *testing.T) {
	p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>2.5.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId><version>5.0.0</version><scope>provided</scope></dependency>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId></dependency>
    <dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId></dependency>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId></dependency>
  </dependencies>
</project>`)

	direct := packagesByName(p.Direct())
	assert.NotContains(t, direct, "junit:junit",
		"a managed test scope must keep the dependency out of the production set")
	assert.NotContains(t, direct, "jakarta.servlet:jakarta.servlet-api",
		"a managed provided scope must keep the dependency out of the production set")

	guava := direct["com.google.guava:guava"]
	require.NotNil(t, guava, "a managed dependency with no scope is still production")
	assert.Equal(t, "31.1-jre", guava.Version)

	// Transitive is every declared dependency regardless of scope, so the
	// managed version still has to reach them.
	all := packagesByName(p.Transitive())
	require.NotNil(t, all["junit:junit"])
	assert.Equal(t, "4.13.2", all["junit:junit"].Version)
}

// A dependency's own scope wins over the managed one, which is what lets a
// module opt a managed test dependency back into its production set.
func TestPomXmlDependencyScopeOverridesTheManagedScope(t *testing.T) {
	p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>2.5.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><scope>compile</scope></dependency>
  </dependencies>
</project>`)

	direct := packagesByName(p.Direct())
	require.Contains(t, direct, "junit:junit")
	assert.Equal(t, "4.13.2", direct["junit:junit"].Version)
}

// <properties> decodes through a custom UnmarshalXML, so what it does with a
// decoding failure is its own decision and has to be asserted on directly: at
// the Parse boundary the outer decoder fails on the same malformed document
// either way, which would make a test here pass whatever UnmarshalXML returned.
func TestPomPropertiesUnmarshal(t *testing.T) {
	decodeProperties := func(t *testing.T, doc string) (pomProperties, error) {
		t.Helper()
		d := xml.NewDecoder(strings.NewReader(doc))
		tok, err := d.Token()
		require.NoError(t, err)
		start, ok := tok.(xml.StartElement)
		require.True(t, ok)

		var p pomProperties
		return p, p.UnmarshalXML(d, start)
	}

	t.Run("a well-formed block decodes every property", func(t *testing.T) {
		props, err := decodeProperties(t,
			`<properties><spring.version>5.3.18</spring.version><jackson.version>2.13.0</jackson.version></properties>`)
		require.NoError(t, err)
		assert.Equal(t, pomProperties{"spring.version": "5.3.18", "jackson.version": "2.13.0"}, props)
	})

	// Swallowing this would leave every version referring to a property in the
	// block unresolvable, and an unresolvable version is a dependency no
	// advisory matches — a silent gap rather than a reported one.
	t.Run("a malformed block is an error", func(t *testing.T) {
		_, err := decodeProperties(t, `<properties><good>1.0</good><bad>&notanentity;</bad></properties>`)
		require.Error(t, err)
	})

	// An early end of document arrives as a syntax error rather than a bare
	// io.EOF, because the decoder is inside an open element. Singling io.EOF out
	// would be a branch that never runs.
	t.Run("a truncated block is an error too", func(t *testing.T) {
		_, err := decodeProperties(t, `<properties><good>1.0</good>`)
		require.Error(t, err)
		assert.NotErrorIs(t, err, io.EOF)
	})
}

// A pom.xml states the project's own licenses in <licenses>, and Maven's
// guidance is that several listed licenses mean the consumer may select any one
// of them. That is SPDX's OR, which is what LicenseExpression renders, so this
// extractor reports a license the same way every other one now does rather than
// being the build manifest that reads none.
func TestPomXmlReadsDeclaredLicenses(t *testing.T) {
	t.Run("a single license passes through as written", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
  <licenses><license>
    <name>Apache License, Version 2.0</name>
    <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
  </license></licenses>
</project>`)
		root := p.Root()
		require.NotNil(t, root)
		assert.Equal(t, "Apache License, Version 2.0", root.License)
	})

	t.Run("several licenses are a choice", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
  <licenses>
    <license><name>EPL-2.0</name></license>
    <license><name>GPL-2.0-with-classpath-exception</name></license>
  </licenses>
</project>`)
		assert.Equal(t, "(EPL-2.0 OR GPL-2.0-with-classpath-exception)", p.Root().License)
	})

	// The url is a link to the terms, not the identity of the terms. A license
	// entry that carries only one names nothing this can report.
	t.Run("a url without a name states no license", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
  <licenses><license><url>https://www.apache.org/licenses/LICENSE-2.0.txt</url></license></licenses>
</project>`)
		assert.Empty(t, p.Root().License)
	})

	t.Run("no licenses block states nothing", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
</project>`)
		assert.Empty(t, p.Root().License)
	})

	// A POM that keeps its license name in a property is stating a license; the
	// raw reference would match nothing, exactly as it would for a version.
	t.Run("a property reference is resolved", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
  <properties><license.name>MIT</license.name></properties>
  <licenses><license><name>${license.name}</name></license></licenses>
</project>`)
		assert.Equal(t, "MIT", p.Root().License)
	})

	// <licenses> describes the project, not what it depends on.
	t.Run("dependencies do not inherit the project's license", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
  <licenses><license><name>MIT</name></license></licenses>
  <dependencies>
    <dependency><groupId>org.example</groupId><artifactId>dep</artifactId><version>1.0.0</version></dependency>
  </dependencies>
</project>`)
		require.Equal(t, "MIT", p.Root().License)
		dep := packagesByName(p.Transitive())["org.example:dep"]
		require.NotNil(t, dep)
		assert.Empty(t, dep.License, "a dependency's license is not stated by this POM")
	})
}

// The shared renderer's bounds apply here too, so a POM cannot put an arbitrary
// amount of text into a field consumers read as an identifier.
func TestPomXmlLicenseIsBounded(t *testing.T) {
	long := strings.Repeat("A", languages.LicenseMaxBytes+1)
	p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>myapp</artifactId><version>1.0.0</version>
  <licenses>
    <license><name>`+long+`</name></license>
    <license><name>MIT</name></license>
  </licenses>
</project>`)
	assert.Equal(t, "MIT", p.Root().License,
		"an oversized name is dropped without taking its sibling with it")
}

// Maven matches a dependency against <dependencyManagement> on groupId,
// artifactId, type and classifier. The same groupId:artifactId is routinely
// published as more than one artifact, and a POM versions each separately, so
// matching on the coordinates alone returns whichever entry happens to come
// first: a wrong version, and with it a wrong set of advisories.
func TestPomXmlManagedMatchUsesTypeAndClassifier(t *testing.T) {
	t.Run("a test-jar takes the test-jar's version", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type><version>2.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type></dependency>
  </dependencies>
</project>`)
		assert.Equal(t, "2.0", packagesByName(p.Transitive())["g:a"].Version)
	})

	t.Run("the plain jar still takes the plain jar's version", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type><version>2.0</version></dependency>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
  </dependencies>
</project>`)
		assert.Equal(t, "1.0", packagesByName(p.Transitive())["g:a"].Version)
	})

	// A native library published per platform is the ordinary classifier case.
	t.Run("a classifier selects its own entry", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><classifier>linux-x86_64</classifier><version>2.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><classifier>linux-x86_64</classifier></dependency>
  </dependencies>
</project>`)
		assert.Equal(t, "2.0", packagesByName(p.Transitive())["g:a"].Version)
	})

	// Maven assumes type jar when none is stated, so the two spellings are the
	// same artifact and have to match each other.
	t.Run("an explicit jar type matches an entry that states none", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>jar</type></dependency>
  </dependencies>
</project>`)
		assert.Equal(t, "1.0", packagesByName(p.Transitive())["g:a"].Version)
	})

	// The key is property-resolved like the coordinates, because either side
	// may write any part of it as a reference.
	t.Run("a property in the type still matches", func(t *testing.T) {
		p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <properties><art.type>test-jar</art.type></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type><version>2.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>${art.type}</type></dependency>
  </dependencies>
</project>`)
		assert.Equal(t, "2.0", packagesByName(p.Transitive())["g:a"].Version)
	})
}

// The managed scope is read off the same key, so an incomplete key leaks a test
// dependency into the production set: the test-jar below matched the plain
// jar's entry, which states no scope, and was reported as production.
func TestPomXmlManagedScopeUsesTheFullKey(t *testing.T) {
	p := parsePom(t, `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type><version>2.0</version><scope>test</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type></dependency>
  </dependencies>
</project>`)

	assert.NotContains(t, packagesByName(p.Direct()), "g:a",
		"a managed test scope on the test-jar must keep it out of the production set")
	assert.Equal(t, "2.0", packagesByName(p.Transitive())["g:a"].Version)
}

// TestOptionalDependenciesAreMarked — an optional dependency is not inherited
// by whoever depends on the declaring package, so anything walking a dependency
// graph has to know. A walk that does not is not slightly over-broad but wrong
// by a factor: log4j-core alone declares 16 optional dependencies, and a
// prototype closure walk that ignored the flag reached 28 packages on a project
// whose real closure is 16.
func TestOptionalDependenciesAreMarked(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(`<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <opt.flag>true</opt.flag>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.12.2</version>
      <optional>true</optional>
    </dependency>
    <dependency>
      <groupId>com.lmax</groupId>
      <artifactId>disruptor</artifactId>
      <version>3.4.2</version>
      <optional>${opt.flag}</optional>
    </dependency>
    <dependency>
      <groupId>org.zeromq</groupId>
      <artifactId>jeromq</artifactId>
      <version>0.4.3</version>
      <optional>false</optional>
    </dependency>
  </dependencies>
</project>`), "pom.xml")
	require.NoError(t, err)
	deps := bom.Transitive()

	require.NotNil(t, deps.Find("com.fasterxml.jackson.core:jackson-databind"))
	assert.True(t, deps.Find("com.fasterxml.jackson.core:jackson-databind").Optional)
	// Read through the same property resolution as every other field.
	assert.True(t, deps.Find("com.lmax:disruptor").Optional, "${opt.flag} resolving to true is optional")

	assert.False(t, deps.Find("org.apache.logging.log4j:log4j-api").Optional, "no <optional> element")
	assert.False(t, deps.Find("org.zeromq:jeromq").Optional, "<optional>false</optional>")
}

// TestUnresolvedOptionalIsNotOptional — a flag that stays a literal
// "${some.flag}" says nothing, and reading it as true would drop a real
// dependency out of a dependent's closure. The safe reading of "unknown" here
// is "inherited", which is what Maven does for a dependency with no <optional>.
func TestUnresolvedOptionalIsNotOptional(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(`<project>
  <groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId><artifactId>thing</artifactId><version>1.0</version>
      <optional>${nowhere.defined}</optional>
    </dependency>
  </dependencies>
</project>`), "pom.xml")
	require.NoError(t, err)

	p := bom.Transitive().Find("com.example:thing")
	require.NotNil(t, p)
	assert.False(t, p.Optional, "an unresolved flag is not an assertion that the dependency is optional")
}

// TestOptionalIsIndependentOfScope pins the two axes apart. A production-scope
// dependency can be optional — the declaring project ships it only if you ask
// for the feature it enables — so neither field can be derived from the other.
func TestOptionalIsIndependentOfScope(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(`<project>
  <groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId><artifactId>compile-optional</artifactId><version>1.0</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>`), "pom.xml")
	require.NoError(t, err)

	// It is compile scope, so it stays in Direct() — the existing production
	// filter is unchanged by this field.
	p := bom.Direct().Find("com.example:compile-optional")
	require.NotNil(t, p, "an optional compile dependency is still declared by this project")
	assert.True(t, p.Optional)
}

// TestNonUTF8PomParses — a POM is not always UTF-8, and Go's encoding/xml
// refuses a declared non-UTF-8 encoding outright rather than falling back. The
// cost is not a mangled character: the whole parse fails, so a project whose
// pom.xml carries an ISO-8859-1 header reports NO dependencies at all.
//
// hamcrest-core-1.3 ships exactly this header, and a generation of artifacts
// published alongside it do too.
func TestNonUTF8PomParses(t *testing.T) {
	// "Café" in ISO-8859-1: the é is a single 0xE9 byte, which is not valid
	// UTF-8, so a decoder that ignored the declared encoding would also fail.
	iso := append([]byte(`<?xml version="1.0" encoding="ISO-8859-1"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.hamcrest</groupId>
  <artifactId>hamcrest-core</artifactId>
  <version>1.3</version>
  <name>Caf`), 0xE9)
	iso = append(iso, []byte(`</name>
  <dependencies>
    <dependency>
      <groupId>org.hamcrest</groupId>
      <artifactId>hamcrest-parent</artifactId>
      <version>1.3</version>
    </dependency>
  </dependencies>
</project>`)...)

	bom, err := (&Extractor{}).Parse(bytes.NewReader(iso), "pom.xml")
	require.NoError(t, err, "a non-UTF-8 POM must parse; failing it reports zero dependencies for the whole project")

	root := bom.Root()
	require.NotNil(t, root)
	assert.Equal(t, "org.hamcrest:hamcrest-core", root.Name)

	dep := bom.Transitive().Find("org.hamcrest:hamcrest-parent")
	require.NotNil(t, dep, "the dependency list must survive the encoding")
	assert.Equal(t, "1.3", dep.Version)
}

// TestUTF8PomStillParses is the control: adding a CharsetReader must not change
// the ordinary case.
func TestUTF8PomStillParses(t *testing.T) {
	bom, err := (&Extractor{}).Parse(strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>
  </dependencies>
</project>`), "pom.xml")
	require.NoError(t, err)
	assert.Equal(t, "31.1-jre", bom.Transitive().Find("com.google.guava:guava").Version)
}
