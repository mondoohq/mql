// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*requirementsTxt)(nil)
)

// Extractor parses a requirements.txt file (the pip/`pip freeze` format) into a
// languages.Bom of Python packages.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "requirements"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	reqs, err := ParseRequirementsTxt(r)
	if err != nil {
		return nil, err
	}

	bom := &requirementsTxt{reqs: reqs}
	if filename != "" {
		bom.evidence = append(bom.evidence, filename)
	}
	return bom, nil
}

// requirementsTxt is a languages.Bom over a parsed requirements.txt.
type requirementsTxt struct {
	reqs     []Requirement
	evidence []string
}

// Root returns nil — requirements.txt has no root project entry.
func (l *requirementsTxt) Root() *languages.Package { return nil }

// Direct returns nil — requirements.txt does not distinguish direct from
// transitive (a `pip freeze` lists the whole flattened set).
func (l *requirementsTxt) Direct() languages.Packages { return nil }

// Transitive returns every pinned requirement. Entries without a pinned version
// (an unconstrained `flask`, or a range like `flask>=2`) are skipped: an SBOM
// component needs a concrete version, and requirements.txt does not resolve one.
func (l *requirementsTxt) Transitive() languages.Packages {
	var packages languages.Packages
	for _, req := range l.reqs {
		if req.Name == "" || req.Version == "" {
			continue
		}
		packages = append(packages, &languages.Package{
			Name:         req.Name,
			Version:      req.Version,
			Purl:         python.NewPackageUrl(req.Name, req.Version),
			Cpes:         python.NewCpes(req.Name, req.Version),
			EvidenceList: python.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
