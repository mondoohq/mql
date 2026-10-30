// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomxml

import (
	"encoding/xml"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
)

// pomProject represents a parsed Maven pom.xml file.
type pomProject struct {
	XMLName    xml.Name   `xml:"project"`
	GroupId    string     `xml:"groupId"`
	ArtifactId string     `xml:"artifactId"`
	Version    string     `xml:"version"`
	Parent     *pomParent `xml:"parent"`
	// Properties are the user-defined ${...} substitutions a POM declares. A
	// version written as ${jackson.version} is extremely common — it is how a
	// project keeps a family of artifacts on one version — and without the bag
	// the dependency's version is the literal property reference, which matches
	// no package and no advisory.
	Properties pomProperties `xml:"properties"`
	// DependencyManagement holds versions declared once for the whole project.
	// A <dependency> under <dependencies> may then omit its <version> entirely,
	// and the version stated here is the one that applies.
	//
	// Only entries written in this POM are read. A <scope>import</scope> entry
	// names a BOM whose own dependencyManagement supplies the versions, and
	// reading that needs the BOM artifact, which is not available from the file
	// on disk. A dependency versioned only by an imported BOM therefore reports
	// no version rather than a guessed one.
	DependencyManagement struct {
		Dependencies []pomDependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
	// Licenses are the licenses the POM declares for the project itself, not for
	// its dependencies. Maven's own guidance is that several listed licenses
	// mean the consumer may select any one of them, so the list is a choice and
	// renders as SPDX's OR.
	//
	// Only this POM's own block is read. Maven inherits <licenses> from a parent
	// POM, and resolving that needs the parent artifact, which is not available
	// from the file on disk. A module that states none reports none rather than
	// guessing at what it would inherit.
	Licenses []pomLicense `xml:"licenses>license"`

	// evidence is a list of file paths where the pom.xml was found.
	evidence []string `json:"-"`
}

// pomProperties decodes <properties> as arbitrary child elements, which is what
// it is: every child element is a user-named property.
type pomProperties map[string]string

func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if *p == nil {
		*p = map[string]string{}
	}
	for {
		tok, err := d.Token()
		if err != nil {
			// Every error reaching here is a decoding failure, an early end of
			// document included: inside an open <properties> element the
			// decoder reports that as an *xml.SyntaxError ("unexpected EOF"),
			// never a bare io.EOF, and a well-formed block returns at its
			// EndElement before EOF is reachable at all. So there is no case to
			// single out, and reporting the failure matters here: a property
			// that silently fails to load makes every version referring to it
			// unresolvable, and an unresolvable version is a dependency no
			// advisory can match.
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var v string
			if err := d.DecodeElement(&v, &t); err != nil {
				return err
			}
			(*p)[t.Name.Local] = strings.TrimSpace(v)
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}

// maxPropertyDepth bounds property resolution. A property may refer to another
// property, and a POM may declare a cycle; the depth cap terminates both.
const maxPropertyDepth = 10

// resolve substitutes ${...} references in s using the project's properties and
// Maven's built-in project coordinates.
//
// An unresolvable reference is returned UNCHANGED, deliberately. A version this
// parser cannot resolve is not a version, and substituting a guess would report
// a dependency at some other version's identity — matching that version's
// advisories and that version's license. Leaving the reference intact keeps the
// gap visible to whatever reads it.
func (p *pomProject) resolve(s string) string {
	for range maxPropertyDepth {
		if !strings.Contains(s, "${") {
			return s
		}
		next := p.expandOnce(s)
		if next == s {
			// Nothing more can be substituted; the rest stays as written.
			return s
		}
		s = next
	}
	return s
}

// expandOnce replaces every ${...} reference it can resolve, once.
func (p *pomProject) expandOnce(s string) string {
	var b strings.Builder
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			b.WriteString(s)
			return b.String()
		}
		end += start
		name := s[start+2 : end]
		b.WriteString(s[:start])
		if v, ok := p.property(name); ok {
			b.WriteString(v)
		} else {
			b.WriteString(s[start : end+1])
		}
		s = s[end+1:]
	}
}

// property resolves one property name: Maven's built-in project coordinates
// first, since a POM cannot redefine them, then the <properties> bag.
func (p *pomProject) property(name string) (string, bool) {
	switch name {
	case "project.version", "pom.version", "version":
		if v := p.effectiveVersion(); v != "" {
			return v, true
		}
		return "", false
	case "project.groupId", "pom.groupId", "groupId":
		if v := p.effectiveGroupId(); v != "" {
			return v, true
		}
		return "", false
	case "project.artifactId", "pom.artifactId", "artifactId":
		if p.ArtifactId != "" {
			return p.ArtifactId, true
		}
		return "", false
	}
	v, ok := p.Properties[name]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// managedDependency finds the <dependencyManagement> entry for a dependency.
//
// groupId and artifactId must already be resolved, and the entry's own
// coordinates are resolved before comparing, because either side may be written
// as a property: a <dependency> commonly says ${project.groupId} where the
// management section says the literal, and a management section importing a
// family of artifacts commonly does the reverse. Comparing the two as written
// matches only when they happen to be spelled the same way, and a miss is
// silent: the dependency simply comes out with no version, which is the outcome
// resolving versions at all was meant to prevent.
func (p *pomProject) managedDependency(dep pomDependency) (pomDependency, bool) {
	want := p.managementKey(dep)
	for _, m := range p.DependencyManagement.Dependencies {
		if p.managementKey(m) == want {
			return m, true
		}
	}
	return pomDependency{}, false
}

// managedVersion returns the version <dependencyManagement> declares for a
// dependency, which is what applies when the <dependency> states none.
func (p *pomProject) managedVersion(dep pomDependency) string {
	m, ok := p.managedDependency(dep)
	if !ok {
		return ""
	}
	return m.Version
}

// effectiveScope reports the scope that applies to a dependency: its own when it
// states one, otherwise the scope <dependencyManagement> declares.
//
// Maven applies a managed scope exactly as it applies a managed version, and the
// two have to be read together. A <dependency> on junit that omits both, against
// a management section declaring 4.13.2 and scope test, is a test dependency at
// 4.13.2 — reading only the version promotes it into the production set with a
// real, matchable purl, so it arrives in an SBOM as something the application
// ships.
func (p *pomProject) effectiveScope(dep pomDependency) string {
	if scope := p.resolve(dep.Scope); scope != "" {
		return scope
	}
	m, ok := p.managedDependency(dep)
	if !ok {
		return ""
	}
	return p.resolve(m.Scope)
}

// isTestOrProvided reports whether a dependency's effective scope makes it a
// non-production dependency.
func (p *pomProject) isTestOrProvided(dep pomDependency) bool {
	scope := p.effectiveScope(dep)
	return scope == "test" || scope == "provided"
}

// pomLicense is one <license> entry. Maven records a name and a link to the
// terms; only the name is carried, because a link to the terms is not the
// identity of the terms, and a URL in a field consumers compare against
// "Apache-2.0" matches nothing while reading as a stated identifier.
type pomLicense struct {
	Name string `xml:"name"`
	URL  string `xml:"url"`
}

// licenseExpression renders the project's declared licenses as a single SPDX
// expression, resolving ${...} references the same way a version is resolved:
// a POM that keeps its license name in a property is stating a license, and
// reporting the raw reference would match nothing.
func (p *pomProject) licenseExpression() string {
	names := make([]string, 0, len(p.Licenses))
	for _, l := range p.Licenses {
		if name := strings.TrimSpace(p.resolve(l.Name)); name != "" {
			names = append(names, name)
		}
	}
	return languages.LicenseExpression(names)
}

// pomParent represents the parent POM reference.
type pomParent struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// pomDependency represents a single <dependency> in a pom.xml.
type pomDependency struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
	// Type and Classifier complete the identity Maven keys a dependency on.
	// The same groupId:artifactId is routinely published as more than one
	// artifact -- the jar and its test-jar, or a native library built per
	// platform -- and dependencyManagement versions each of them separately.
	// Matching without these picks whichever entry comes first.
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
}

// defaultDependencyType is the type Maven assumes when a dependency states
// none, so an entry written without <type> and one written as <type>jar</type>
// are the same artifact and have to compare equal.
const defaultDependencyType = "jar"

// managementKey is the identity Maven matches a dependency against
// dependencyManagement on: groupId, artifactId, type and classifier. Every part
// is property-resolved for the same reason the coordinates are, since either
// side may write any of them as a reference.
func (p *pomProject) managementKey(dep pomDependency) [4]string {
	typ := strings.TrimSpace(p.resolve(dep.Type))
	if typ == "" {
		typ = defaultDependencyType
	}
	return [4]string{
		strings.TrimSpace(p.resolve(dep.GroupId)),
		strings.TrimSpace(p.resolve(dep.ArtifactId)),
		typ,
		strings.TrimSpace(p.resolve(dep.Classifier)),
	}
}

// effectiveGroupId returns the project's groupId, inheriting from parent if not set.
func (p *pomProject) effectiveGroupId() string {
	if p.GroupId != "" {
		return p.GroupId
	}
	if p.Parent != nil {
		return p.Parent.GroupId
	}
	return ""
}

// effectiveVersion returns the project's version, inheriting from parent if not set.
func (p *pomProject) effectiveVersion() string {
	if p.Version != "" {
		return p.Version
	}
	if p.Parent != nil {
		return p.Parent.Version
	}
	return ""
}
