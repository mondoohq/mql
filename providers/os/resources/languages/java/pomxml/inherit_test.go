// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomxml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapResolver serves POMs from an in-memory map, so the walk is tested without
// touching a real local repository.
type mapResolver struct {
	poms  map[string]string
	calls []string
}

func (m *mapResolver) ResolvePom(g, a, v string) ([]byte, bool) {
	key := g + ":" + a + ":" + v
	m.calls = append(m.calls, key)
	p, ok := m.poms[key]
	if !ok {
		return nil, false
	}
	return []byte(p), true
}

// versionOf returns the resolved version of one dependency, which is the value
// the whole feature exists to produce.
func versionOf(t *testing.T, bom *pomProject, name string) string {
	t.Helper()
	for _, p := range bom.Transitive() {
		if p.Name == name {
			return p.Version
		}
	}
	t.Fatalf("dependency %q not found in %v", name, bom.Transitive())
	return ""
}

func parseWith(t *testing.T, pom string, r ParentResolver) *pomProject {
	t.Helper()
	e := &Extractor{Parents: r}
	bom, err := e.Parse(strings.NewReader(pom), "pom.xml")
	require.NoError(t, err)
	return bom.(*pomProject)
}

// childPom is the shape this whole file is about: a dependency declared with no
// <version> at all, which is the standard Spring Boot layout.
const childPom = `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>4.1.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
    </dependency>
  </dependencies>
</project>`

// TestInheritResolvesVersionThroughParentChainAndProperty is the headline case,
// reduced from the real spring-petclinic chain: the version is three files away,
// behind a property the grandparent declares.
//
// Without inheritance the dependency comes out with an EMPTY version, and a purl
// with no version matches no advisory and no registry — the dependency is
// silently exempt from vulnerability correlation.
func TestInheritResolvesVersionThroughParentChainAndProperty(t *testing.T) {
	r := &mapResolver{poms: map[string]string{
		"org.springframework.boot:spring-boot-starter-parent:4.1.0": `<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-dependencies</artifactId>
    <version>4.1.0</version>
  </parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>4.1.0</version>
</project>`,
		"org.springframework.boot:spring-boot-dependencies:4.1.0": `<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>4.1.0</version>
  <properties>
    <h2.version>2.4.240</h2.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <version>${h2.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`,
	}}

	got := parseWith(t, childPom, r)
	assert.Equal(t, "2.4.240", versionOf(t, got, "com.h2database:h2"))
}

// TestInheritWithoutResolverLeavesVersionEmpty pins the hermetic default. With
// no resolver the parser must behave exactly as it did before this feature: the
// parent is not read, so the version is not known.
func TestInheritWithoutResolverLeavesVersionEmpty(t *testing.T) {
	got := parseWith(t, childPom, nil)
	assert.Equal(t, "", versionOf(t, got, "com.h2database:h2"))
}

// TestInheritUnreadableParentLeavesVersionEmpty is the load-bearing safety rule.
//
// When the parent artifact is not on disk — a CI runner that never ran Maven —
// the version stays EMPTY. It is never filled from a nearby version in the
// repository and never from "latest". A wrong version is worse than an absent
// one: it correlates the project against another release's advisories, which can
// both invent a vulnerability the user does not have and conceal one they do.
func TestInheritUnreadableParentLeavesVersionEmpty(t *testing.T) {
	r := &mapResolver{poms: map[string]string{}} // nothing resolves
	got := parseWith(t, childPom, r)
	assert.Equal(t, "", versionOf(t, got, "com.h2database:h2"))
	assert.Contains(t, r.calls, "org.springframework.boot:spring-boot-starter-parent:4.1.0",
		"the parent should have been requested even though it could not be served")
}

// TestInheritImportedBomSuppliesVersion covers the other way Maven states a
// version once: a <scope>import</scope> BOM rather than a parent. A project with
// no <parent> at all still inherits from it.
func TestInheritImportedBomSuppliesVersion(t *testing.T) {
	pom := `<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>2.17.1</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{
		"com.fasterxml.jackson:jackson-bom:2.17.1": `<project>
  <groupId>com.fasterxml.jackson</groupId>
  <artifactId>jackson-bom</artifactId>
  <version>2.17.1</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.17.1</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`,
	}}

	got := parseWith(t, pom, r)
	assert.Equal(t, "2.17.1", versionOf(t, got, "com.fasterxml.jackson.core:jackson-databind"))
}

// TestInheritNearerDefinitionWins pins Maven's precedence rule. The project's own
// dependencyManagement overrides what it would inherit — getting this backwards
// would report the parent's version for a dependency the project deliberately
// pinned elsewhere, which is the "confident wrong answer" case.
func TestInheritNearerDefinitionWins(t *testing.T) {
	pom := `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{
		"com.example:parent:1.0.0": `<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <version>1.1.1</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`,
	}}

	got := parseWith(t, pom, r)
	assert.Equal(t, "9.9.9", versionOf(t, got, "com.h2database:h2"),
		"the project's own dependencyManagement must win over the inherited one")
}

// TestInheritOwnPropertyWinsOverInherited is the same precedence rule for
// properties: a project overriding ${h2.version} is the documented way to move a
// managed dependency off the parent's version.
func TestInheritOwnPropertyWinsOverInherited(t *testing.T) {
	pom := `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <h2.version>9.9.9</h2.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{
		"com.example:parent:1.0.0": `<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <h2.version>1.1.1</h2.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <version>${h2.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`,
	}}

	got := parseWith(t, pom, r)
	assert.Equal(t, "9.9.9", versionOf(t, got, "com.h2database:h2"))
}

// TestInheritCycleTerminates guards against a POM chain that loops. A parent
// naming its own child is malformed, but a scanner reads whatever it is handed
// and must not hang on it.
func TestInheritCycleTerminates(t *testing.T) {
	pom := `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{
		// parent points back at the child, and at itself
		"com.example:parent:1.0.0": `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
</project>`,
		"com.example:app:1.0.0": `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
</project>`,
	}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		got := parseWith(t, pom, r)
		assert.Equal(t, "", versionOf(t, got, "com.h2database:h2"))
	}()
	<-done

	// The child is seeded as visited, so the cycle back to it is never fetched.
	assert.NotContains(t, r.calls, "com.example:app:1.0.0")
}

// TestInheritUnresolvedPropertyCoordinateIsNotFetched pins that a parent
// coordinate still carrying a ${...} reference is not looked up. Asking for a
// literal "${spring.version}" cannot succeed, and on a filesystem-backed
// resolver it is a lookup of an attacker-influenced path.
func TestInheritUnresolvedPropertyCoordinateIsNotFetched(t *testing.T) {
	pom := `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>${undefined.version}</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{}}
	got := parseWith(t, pom, r)
	assert.Equal(t, "", versionOf(t, got, "com.h2database:h2"))
	assert.Empty(t, r.calls, "a coordinate with an unresolved property must not be requested")
}

// TestInheritManagedScopeIsInherited pins that scope travels with the version.
//
// Reading only the version would promote an inherited test dependency into the
// production set with a real, matchable purl — so it arrives in an SBOM as
// something the application ships. Direct() must still exclude it.
func TestInheritManagedScopeIsInherited(t *testing.T) {
	pom := `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{
		"com.example:parent:1.0.0": `<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13.2</version>
        <scope>test</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`,
	}}

	got := parseWith(t, pom, r)
	assert.Equal(t, "4.13.2", versionOf(t, got, "junit:junit"), "the managed version is inherited")
	for _, p := range got.Direct() {
		assert.NotEqual(t, "junit:junit", p.Name,
			"an inherited test scope must keep the dependency out of the production set")
	}
}

// TestInheritMalformedImportKeepsItsManagedVersion covers the entry that says
// <scope>import</scope> without <type>pom</type>.
//
// Maven honours import only for type pom (the default type is jar), so such an
// entry is malformed. Treating it as a BOM would skip it from the management
// merge and look it up as a POM it is not — and when that lookup fails, as it
// does here, the version it states is lost. Read strictly it stays an ordinary
// management entry and the version survives.
func TestInheritMalformedImportKeepsItsManagedVersion(t *testing.T) {
	pom := `<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <version>2.4.240</version>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
    </dependency>
  </dependencies>
</project>`
	r := &mapResolver{poms: map[string]string{}} // the bogus "BOM" resolves to nothing

	got := parseWith(t, pom, r)
	assert.Equal(t, "2.4.240", versionOf(t, got, "com.h2database:h2"),
		"an import entry without type=pom is not a BOM; its managed version must survive")
	assert.Empty(t, r.calls, "a non-pom entry must not be fetched as a POM")
}

// TestInheritBomImportRequiresTypePom is the positive half of the same rule: a
// well-formed BOM import (scope import AND type pom) is still followed.
func TestInheritBomImportRequiresTypePom(t *testing.T) {
	assert.True(t, isBomImport(pomDependency{Scope: "import", Type: "pom"}))
	assert.False(t, isBomImport(pomDependency{Scope: "import"}), "default type is jar, not pom")
	assert.False(t, isBomImport(pomDependency{Scope: "import", Type: "jar"}))
	assert.False(t, isBomImport(pomDependency{Scope: "compile", Type: "pom"}))
}
