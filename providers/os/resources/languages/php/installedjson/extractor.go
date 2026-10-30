// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package installedjson

import (
	"encoding/json"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/php"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*installedJson)(nil)
)

// Extractor parses vendor/composer/installed.json files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "installedjson"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var ij installedJson
	if err := json.NewDecoder(r).Decode(&ij); err != nil {
		return nil, err
	}

	if filename != "" {
		ij.evidence = append(ij.evidence, filename)
	}

	return &ij, nil
}

// Root returns nil — installed.json does not describe the root project.
func (ij *installedJson) Root() *languages.Package {
	return nil
}

// Direct returns nil — installed.json has no dev/prod distinction.
func (ij *installedJson) Direct() languages.Packages {
	return nil
}

// Transitive returns all installed packages.
func (ij *installedJson) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pkg := range ij.Packages {
		packages = append(packages, &languages.Package{
			Name:    pkg.Name,
			Version: pkg.Version,
			// installed.json records the license as an array, which means a
			// choice among them; LicenseExpression renders that as SPDX.
			License:      languages.LicenseExpression(pkg.License),
			Description:  pkg.Description,
			Purl:         php.NewPackageUrl(pkg.Name, pkg.Version),
			Cpes:         php.NewCpes(pkg.Name, pkg.Version),
			EvidenceList: php.NewEvidenceList(ij.evidence),
		})
	}
	return packages
}
