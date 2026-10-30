// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagesconfig

import (
	"encoding/xml"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*packagesConfig)(nil)
)

// Extractor parses legacy NuGet packages.config XML files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "packagesconfig"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var config packagesConfig
	if err := xml.NewDecoder(r).Decode(&config); err != nil {
		return nil, err
	}

	if filename != "" {
		config.evidence = append(config.evidence, filename)
	}

	return &config, nil
}

// Root returns nil — packages.config does not describe the root project.
func (c *packagesConfig) Root() *languages.Package {
	return nil
}

// Direct returns non-development packages.
func (c *packagesConfig) Direct() languages.Packages {
	var direct languages.Packages
	for _, pkg := range c.Packages {
		if pkg.isDev() {
			continue
		}
		direct = append(direct, makePackage(pkg, c.evidence))
	}
	return direct
}

// Transitive returns all packages.
func (c *packagesConfig) Transitive() languages.Packages {
	var all languages.Packages
	for _, pkg := range c.Packages {
		all = append(all, makePackage(pkg, c.evidence))
	}
	return all
}

func makePackage(pkg configPackage, evidence []string) *languages.Package {
	return &languages.Package{
		Name:         pkg.Id,
		Version:      pkg.Version,
		Purl:         dotnet.NewPackageUrl(pkg.Id, pkg.Version),
		Cpes:         dotnet.NewCpes(pkg.Id, pkg.Version),
		EvidenceList: dotnet.NewEvidenceList(evidence),
	}
}
