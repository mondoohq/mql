// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package csproj

import (
	"encoding/xml"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*project)(nil)
)

// Extractor parses .NET project files (.csproj, .fsproj, .vbproj) for PackageReference elements.
type Extractor struct {
	// CentralVersions, when set, supplies the versions Central Package
	// Management assigns the project (see CentralVersionResolver): the
	// version of a PackageReference that states none.
	//
	// Left nil the parser stays hermetic and behaves exactly as before: a
	// PackageReference without a Version (or VersionOverride) has no version.
	CentralVersions CentralVersionResolver
}

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
	if e.CentralVersions != nil {
		if central := e.CentralVersions.CentralPackageVersions(filename); len(central) > 0 {
			proj.central = make(map[string]string, len(central))
			for id, v := range central {
				proj.central[strings.ToLower(id)] = v
			}
		}
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
		direct = append(direct, makePackage(ref, p.versionOf(ref), p.evidence))
	}
	return direct
}

// Transitive returns all PackageReferences (csproj only declares direct deps).
func (p *project) Transitive() languages.Packages {
	var all languages.Packages
	for _, ref := range p.allPackageRefs() {
		all = append(all, makePackage(ref, p.versionOf(ref), p.evidence))
	}
	return all
}

// versionOf is the version a PackageReference resolves to: its own Version,
// else its VersionOverride, else the centrally managed one.
func (p *project) versionOf(ref packageReference) string {
	if v := ref.version(); v != "" {
		return v
	}
	if v := ref.versionOverride(); v != "" {
		return v
	}
	return p.central[strings.ToLower(ref.Include)]
}

func makePackage(ref packageReference, version string, evidence []string) *languages.Package {
	return &languages.Package{
		Name:         ref.Include,
		Version:      version,
		Purl:         dotnet.NewPackageUrl(ref.Include, version),
		Cpes:         dotnet.NewCpes(ref.Include, version),
		EvidenceList: dotnet.NewEvidenceList(evidence),
	}
}
