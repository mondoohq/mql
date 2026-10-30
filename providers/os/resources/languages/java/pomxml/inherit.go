// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomxml

import (
	"bytes"
	"strings"
)

// Inheriting a POM's versions from the artifacts it points at.
//
// A pom.xml routinely declares a dependency with no <version> at all:
//
//	<dependency>
//	  <groupId>com.h2database</groupId>
//	  <artifactId>h2</artifactId>
//	</dependency>
//
// That is not unusual, it is the standard Spring Boot layout and the shape of
// any project with a corporate parent: the version is stated once, in a parent
// POM or an imported BOM, and inherited. Reading only this file yields no
// version, and a purl with no version matches no advisory and no registry — so
// the dependency is silently exempt from the vulnerability correlation and
// licence lookup a caller believes it ran.
//
// The parent's coordinates are right there in <parent>, and on a machine that
// has built the project its POM is already on disk. What is missing is
// permission to go and read it: the parser is deliberately hermetic, and a
// parser that reaches into $HOME on its own is neither testable nor
// predictable. So the caller supplies the artifacts through ParentResolver, and
// with none supplied the parser behaves exactly as it did before.
//
// What is NOT done here matters as much. A version no readable POM supplies
// stays empty. There is no "nearest version in the local repository" fallback
// and no "latest wins": a wrong version is worse than an absent one, because it
// correlates the project against a different release's advisories, which can
// both invent a vulnerability the user does not have and conceal one they do.

// ParentResolver supplies the POM for a parent or imported-BOM coordinate.
//
// A false return is a GAP — the artifact could not be read — never an assertion
// that the coordinate does not exist. Callers treat it as "this version stays
// unresolved", which is the same state as having no resolver at all.
type ParentResolver interface {
	ResolvePom(groupID, artifactID, version string) ([]byte, bool)
}

const (
	// maxInheritDepth bounds the parent/BOM chain. Real chains are two or three
	// links (project → starter-parent → dependencies-BOM); anything deeper is a
	// malformed or hostile POM, not a project.
	maxInheritDepth = 16
	// maxInheritPoms bounds the total artifacts read for one project. A BOM may
	// import several BOMs, so the reachable set is a graph rather than a chain.
	maxInheritPoms = 128
)

// inherit merges the properties and dependencyManagement reachable through this
// POM's parent chain and imported BOMs into the project, so the existing
// version and scope resolution finds them.
//
// Maven's precedence is that the nearer definition wins: a property or a managed
// version stated by the project overrides the one it would inherit. That falls
// out of how the merge is written — a property is only filled in when absent,
// and inherited management entries are APPENDED, so managedDependency's
// first-match scan still finds the project's own entry first.
func (p *pomProject) inherit(r ParentResolver) {
	if r == nil {
		return
	}
	st := &inheritState{resolver: r, seen: map[string]bool{}}
	// The project itself is "seen" so a POM naming itself as its own parent —
	// or a cycle back to it — terminates.
	st.seen[coordKey(p.effectiveGroupId(), p.ArtifactId, p.effectiveVersion())] = true
	st.walk(p, p, 0)
}

type inheritState struct {
	resolver ParentResolver
	seen     map[string]bool
	read     int
}

// walk merges src's inheritable state into dst, then recurses into src's own
// parent and imported BOMs.
//
// dst is always the project being resolved; src moves up the chain. Merging
// into the project directly (rather than composing an effective POM) keeps every
// existing lookup — resolve, managedDependency, effectiveScope — working
// unchanged on the merged bag.
func (st *inheritState) walk(dst, src *pomProject, depth int) {
	if depth >= maxInheritDepth || st.read >= maxInheritPoms {
		return
	}

	// A BOM import is resolved against the properties known SO FAR, which is why
	// the merge happens before the recursion: a BOM whose version is
	// ${spring-boot.version} needs the property that names it.
	if src != dst {
		dst.mergeFrom(src)
	}

	// Imported BOMs first: Maven gives an imported BOM's managed versions
	// precedence over those inherited from a parent, and appending them first
	// preserves that ordering for managedDependency's first-match scan.
	for _, imp := range src.bomImports() {
		g := dst.resolve(imp.GroupId)
		a := dst.resolve(imp.ArtifactId)
		v := dst.resolve(imp.Version)
		if bom := st.load(g, a, v); bom != nil {
			st.walk(dst, bom, depth+1)
		}
	}

	if src.Parent == nil {
		return
	}
	pg := dst.resolve(src.Parent.GroupId)
	pa := dst.resolve(src.Parent.ArtifactId)
	pv := dst.resolve(src.Parent.Version)
	if parent := st.load(pg, pa, pv); parent != nil {
		st.walk(dst, parent, depth+1)
	}
}

// load fetches and parses one POM, or returns nil when it cannot be read or has
// already been visited.
func (st *inheritState) load(groupID, artifactID, version string) *pomProject {
	if groupID == "" || artifactID == "" || version == "" {
		return nil
	}
	// An unresolved ${...} reference is not a coordinate; asking the resolver for
	// it would at best miss and at worst look up a literal directory name.
	if hasUnresolvedProperty(groupID) || hasUnresolvedProperty(artifactID) || hasUnresolvedProperty(version) {
		return nil
	}
	key := coordKey(groupID, artifactID, version)
	if st.seen[key] {
		return nil
	}
	st.seen[key] = true

	if st.read >= maxInheritPoms {
		return nil
	}
	data, ok := st.resolver.ResolvePom(groupID, artifactID, version)
	if !ok || len(data) == 0 {
		return nil
	}
	st.read++

	parsed, err := parsePomXml(bytesReader(data))
	if err != nil {
		return nil
	}
	return parsed
}

// mergeFrom fills in what dst does not state itself from src.
//
// Properties are filled only where absent, and management entries are appended
// after dst's own, so in both cases the nearer definition keeps precedence.
func (p *pomProject) mergeFrom(src *pomProject) {
	if len(src.Properties) > 0 {
		if p.Properties == nil {
			p.Properties = pomProperties{}
		}
		for k, v := range src.Properties {
			if _, ok := p.Properties[k]; !ok {
				p.Properties[k] = v
			}
		}
	}
	for _, d := range src.DependencyManagement.Dependencies {
		// A BOM import is an instruction to read another POM, not a version for
		// some artifact called "import"; it is followed by walk, not merged.
		if isBomImport(d) {
			continue
		}
		p.DependencyManagement.Dependencies = append(p.DependencyManagement.Dependencies, d)
	}
}

// bomImports returns the <dependencyManagement> entries that import another
// BOM's managed versions (`<scope>import</scope>`, type pom).
func (p *pomProject) bomImports() []pomDependency {
	var out []pomDependency
	for _, d := range p.DependencyManagement.Dependencies {
		if isBomImport(d) {
			out = append(out, d)
		}
	}
	return out
}

// isBomImport reports whether a <dependencyManagement> entry is an instruction
// to read another POM's managed versions.
//
// Maven honours `<scope>import</scope>` ONLY for `<type>pom</type>`, and the
// default type is jar — so an entry that says import without saying pom is not
// a BOM import, it is malformed, and Maven fails the build on it.
//
// Matching strictly is also the safer of the two readings, because the mistakes
// are not symmetric. An entry wrongly treated as a BOM is skipped from the
// management merge AND looked up as a POM it is not, so if that lookup fails its
// version is lost entirely. An entry wrongly treated as ordinary management
// merely keeps its version available. Strict costs nothing when the POM is
// well-formed and loses nothing when it is not.
func isBomImport(d pomDependency) bool {
	return strings.TrimSpace(d.Scope) == "import" && strings.TrimSpace(d.Type) == "pom"
}

func coordKey(groupID, artifactID, version string) string {
	return groupID + ":" + artifactID + ":" + version
}

// hasUnresolvedProperty reports whether a string still carries a ${...}
// reference that resolution could not expand. Such a string is not a coordinate:
// looking it up would query a literal "${spring.version}" directory.
func hasUnresolvedProperty(s string) bool { return strings.Contains(s, "${") }

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
