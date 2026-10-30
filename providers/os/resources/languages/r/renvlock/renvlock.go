// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package renvlock

import (
	"encoding/json"
	"io"
	"slices"

	"go.mondoo.com/mql/providers/os/resources/languages"
	rlang "go.mondoo.com/mql/providers/os/resources/languages/r"
	"go.mondoo.com/mql/sbom"
)

// renvLockfile represents the structure of an renv.lock file.
type renvLockfile struct {
	R        renvR                  `json:"R"`
	Packages map[string]renvPackage `json:"Packages"`
}

type renvR struct {
	Version string `json:"Version"`
}

type renvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Source     string `json:"Source"`
	Repository string `json:"Repository"`
}

// Extractor parses renv.lock files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "R renv.lock Extractor"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lockfile renvLockfile
	if err := json.NewDecoder(r).Decode(&lockfile); err != nil {
		return nil, err
	}

	bom := &renvBom{
		transitive: make(languages.Packages, 0, len(lockfile.Packages)),
	}

	for _, pkg := range lockfile.Packages {
		if pkg.Package == "" {
			continue
		}

		bom.transitive = append(bom.transitive, &languages.Package{
			Name:    pkg.Package,
			Version: pkg.Version,
			Purl:    rlang.NewPackageUrl(pkg.Package, pkg.Version),
			EvidenceList: []*sbom.Evidence{
				rlang.NewEvidence(filename),
			},
		})
	}

	slices.SortFunc(bom.transitive, func(a, b *languages.Package) int {
		if a.Name != b.Name {
			if a.Name < b.Name {
				return -1
			}
			return 1
		}
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return 0
	})

	return bom, nil
}

type renvBom struct {
	transitive languages.Packages
}

func (b *renvBom) Root() *languages.Package {
	return nil
}

func (b *renvBom) Direct() languages.Packages {
	return nil
}

func (b *renvBom) Transitive() languages.Packages {
	return b.transitive
}
