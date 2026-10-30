// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomxml

import (
	"encoding/xml"
	"io"
	"strings"

	"golang.org/x/net/html/charset"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*pomProject)(nil)
)

// Extractor parses Maven pom.xml files to extract project dependencies.
type Extractor struct {
	// Parents, when set, supplies the parent and imported-BOM POMs whose
	// <properties> and <dependencyManagement> a project inherits its versions
	// from. Declaring a dependency without a <version> and inheriting it is the
	// standard Spring Boot layout, and reading the pom.xml alone leaves those
	// dependencies with no version — hence no matchable purl (see inherit.go).
	//
	// Left nil the parser stays hermetic and behaves exactly as before: only
	// this POM's own dependencyManagement is consulted, and a version it does
	// not state stays empty.
	Parents ParentResolver
}

func (e *Extractor) Name() string {
	return "pomxml"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	project, err := parsePomXml(r)
	if err != nil {
		return nil, err
	}

	// Before any version is read: depToPackage and effectiveScope both resolve
	// against the property bag and management list, so what is inherited has to
	// be in place first.
	project.inherit(e.Parents)

	if filename != "" {
		project.evidence = append(project.evidence, filename)
	}

	return project, nil
}

// parsePomXml reads and parses a Maven pom.xml file.
//
// The decoder is given a CharsetReader because a POM is not always UTF-8 and
// Go's encoding/xml refuses a declared non-UTF-8 encoding outright rather than
// falling back. Without one, `<?xml version="1.0" encoding="ISO-8859-1"?>` — the
// header on hamcrest-core and a generation of artifacts published with it —
// fails the whole parse, and a project whose pom.xml carries it reports NO
// dependencies at all. That is the silent-empty-inventory failure, arriving
// through the character encoding rather than through a missing manifest.
func parsePomXml(r io.Reader) (*pomProject, error) {
	var project pomProject
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&project); err != nil {
		return nil, err
	}
	return &project, nil
}

// Root returns the project itself as the root package.
func (p *pomProject) Root() *languages.Package {
	groupId := p.effectiveGroupId()
	version := p.effectiveVersion()

	if groupId == "" && p.ArtifactId == "" {
		return nil
	}

	name := p.ArtifactId
	if groupId != "" {
		name = groupId + ":" + p.ArtifactId
	}

	return &languages.Package{
		Name:    name,
		Version: version,
		// <licenses> describes this project, not its dependencies, so it
		// belongs on the root package and nowhere else.
		License:      p.licenseExpression(),
		Purl:         java.NewPackageUrl(groupId, p.ArtifactId, version),
		Cpes:         java.NewCpes(groupId, p.ArtifactId, version),
		EvidenceList: java.NewEvidenceList(p.evidence),
	}
}

// Direct returns production dependencies (scope != test, scope != provided).
func (p *pomProject) Direct() languages.Packages {
	var direct languages.Packages
	for _, dep := range p.Dependencies {
		if p.isTestOrProvided(dep) {
			continue
		}
		direct = append(direct, p.depToPackage(dep))
	}
	return direct
}

// Transitive returns all declared dependencies (direct only — pom.xml does not
// resolve transitives without downloading the full dependency tree).
func (p *pomProject) Transitive() languages.Packages {
	var all languages.Packages
	for _, dep := range p.Dependencies {
		all = append(all, p.depToPackage(dep))
	}
	return all
}

// depToPackage renders one <dependency> as a package, resolving the ${...}
// property references and the <dependencyManagement> version that decide what
// the dependency's identity actually is.
//
// Both matter beyond tidiness. A version left as the literal "${jackson.version}"
// produces a purl no advisory database and no package registry can match, so the
// dependency is silently exempt from vulnerability correlation and from licence
// lookup alike.
func (p *pomProject) depToPackage(dep pomDependency) *languages.Package {
	groupId := p.resolve(dep.GroupId)
	artifactId := p.resolve(dep.ArtifactId)

	version := p.resolve(dep.Version)
	if version == "" {
		// No <version> on the dependency: the project's <dependencyManagement>
		// is where it is declared, which is the standard way a multi-module
		// project states a version once.
		version = p.resolve(p.managedVersion(dep))
	}

	name := artifactId
	if groupId != "" {
		name = groupId + ":" + artifactId
	}

	// <optional>true</optional> is read through the same property resolution as
	// every other field: a POM may state it as ${some.flag}, and an unresolved
	// one is not optional.
	optional := strings.EqualFold(strings.TrimSpace(p.resolve(dep.Optional)), "true")

	return &languages.Package{
		Name:         name,
		Version:      version,
		Optional:     optional,
		Purl:         java.NewPackageUrl(groupId, artifactId, version),
		Cpes:         java.NewCpes(groupId, artifactId, version),
		EvidenceList: java.NewEvidenceList(p.evidence),
	}
}
