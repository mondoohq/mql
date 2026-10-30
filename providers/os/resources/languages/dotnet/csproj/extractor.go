// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package csproj

import (
	"encoding/xml"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*project)(nil)
)

// Extractor parses .NET project files (.csproj, .fsproj, .vbproj) for PackageReference elements.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "csproj"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var proj project
	if err := xml.NewDecoder(r).Decode(&proj); err != nil {
		return nil, err
	}

	if filename != "" {
		proj.evidence = append(proj.evidence, filename)
	}

	return &proj, nil
}

// allPackageRefs returns all PackageReference elements across all ItemGroups.
func (p *project) allPackageRefs() []packageReference {
	var refs []packageReference
	for _, ig := range p.ItemGroups {
		refs = append(refs, ig.PackageReferences...)
	}
	return refs
}

// Root returns nil — project files do not expose the project itself as a package.
func (p *project) Root() *languages.Package {
	return nil
}

// Direct returns non-development PackageReferences.
func (p *project) Direct() languages.Packages {
	var direct languages.Packages
	for _, ref := range p.allPackageRefs() {
		if ref.isDev() {
			continue
		}
		direct = append(direct, makePackage(ref, p.evidence))
	}
	return direct
}

// Transitive returns all PackageReferences (csproj only declares direct deps).
func (p *project) Transitive() languages.Packages {
	var all languages.Packages
	for _, ref := range p.allPackageRefs() {
		all = append(all, makePackage(ref, p.evidence))
	}
	return all
}

func makePackage(ref packageReference, evidence []string) *languages.Package {
	version := ref.version()
	return &languages.Package{
		Name:         ref.Include,
		Version:      version,
		Purl:         dotnet.NewPackageUrl(ref.Include, version),
		Cpes:         dotnet.NewCpes(ref.Include, version),
		EvidenceList: dotnet.NewEvidenceList(evidence),
	}
}
