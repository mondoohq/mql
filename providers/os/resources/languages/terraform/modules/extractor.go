// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

// Package modules reads the module manifest `terraform init` writes to
// .terraform/modules/modules.json.
//
// Where the configuration states the modules this code calls, the manifest
// states the modules Terraform actually installed — the called ones and, in
// turn, the ones those call. It only exists after init has run and is normally
// not committed, so it complements the configuration rather than replacing it.
package modules

import (
	"encoding/json"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/terraform"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*moduleManifest)(nil)
)

// Extractor parses .terraform/modules/modules.json.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "terraform-modules"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	manifest := &moduleManifest{}
	if err := json.NewDecoder(r).Decode(manifest); err != nil {
		return nil, err
	}
	if filename != "" {
		manifest.evidence = append(manifest.evidence, filename)
	}
	return manifest, nil
}

type moduleManifest struct {
	Modules  []moduleRecord `json:"Modules"`
	evidence []string
}

type moduleRecord struct {
	// Key identifies the module call. A top-level call is named by itself
	// ("vpc"); a call made by that module is qualified ("vpc.subnets"), which
	// is what separates a direct dependency from a transitive one.
	Key string `json:"Key"`
	// Source is the module source address as the caller wrote it.
	Source string `json:"Source"`
	// Version is the resolved version, set for registry modules only.
	Version string `json:"Version"`
	// Dir is where the module was installed.
	Dir string `json:"Dir"`
}

func (m *moduleManifest) Root() *languages.Package {
	return nil
}

func (m *moduleManifest) Direct() languages.Packages {
	return m.packages(false)
}

func (m *moduleManifest) Transitive() languages.Packages {
	return m.packages(true)
}

func (m *moduleManifest) packages(transitive bool) languages.Packages {
	var packages languages.Packages
	evidence := terraform.NewEvidenceList(m.evidence)

	for _, record := range m.Modules {
		// The root record describes the configuration itself.
		if record.Key == "" {
			continue
		}
		if strings.Contains(record.Key, ".") != transitive {
			continue
		}

		source := terraform.ClassifyModuleSource(record.Source)
		purl := terraform.NewModulePackageUrl(source, record.Version)
		if purl == "" {
			// A local path, or a fetcher with no stable public coordinate. A
			// module a dependency keeps inside its own tree is not a separate
			// artifact.
			continue
		}

		packages = append(packages, &languages.Package{
			Name:         terraform.ModuleName(source),
			Type:         terraform.PackageTypeModule,
			Version:      record.Version,
			Purl:         purl,
			Origin:       record.Source,
			Scope:        languages.PackageScopeProd,
			EvidenceList: evidence,
		})
	}

	return packages
}
