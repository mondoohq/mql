// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packageresolved

import (
	"encoding/json"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/swift"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*packageResolved)(nil)
)

// Extractor parses Swift Package Manager Package.resolved files (v1 and v2).
type Extractor struct{}

func (e *Extractor) Name() string {
	return "packageresolved"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var pr packageResolved

	if filename != "" {
		pr.evidence = append(pr.evidence, filename)
	}

	if err := json.NewDecoder(r).Decode(&pr); err != nil {
		return nil, err
	}

	return &pr, nil
}

// Root returns nil — Package.resolved does not describe the root project.
func (pr *packageResolved) Root() *languages.Package {
	return nil
}

// Direct returns nil — Package.resolved does not distinguish direct from transitive.
func (pr *packageResolved) Direct() languages.Packages {
	return nil
}

// Transitive returns all resolved dependencies.
func (pr *packageResolved) Transitive() languages.Packages {
	var packages languages.Packages

	if pr.Version >= 2 || (pr.Object == nil && len(pr.Pins) > 0) {
		// V2 format: pins at top level
		for _, p := range pr.Pins {
			packages = append(packages, &languages.Package{
				Name:         p.Identity,
				Version:      p.State.Version,
				Purl:         swift.NewSpmPackageUrl(p.Identity, p.State.Version),
				Cpes:         swift.NewCpes(p.Identity, p.State.Version),
				EvidenceList: swift.NewEvidenceList(pr.evidence),
			})
		}
	} else if pr.Object != nil {
		// V1 format: pins inside object
		for _, p := range pr.Object.Pins {
			packages = append(packages, &languages.Package{
				Name:         p.Package,
				Version:      p.State.Version,
				Purl:         swift.NewSpmPackageUrl(p.Package, p.State.Version),
				Cpes:         swift.NewCpes(p.Package, p.State.Version),
				EvidenceList: swift.NewEvidenceList(pr.evidence),
			})
		}
	}

	return packages
}
