// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package depsjson

import (
	"encoding/json"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*depsJson)(nil)
)

// Extractor parses .NET *.deps.json runtime dependency manifests.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "depsjson"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var deps depsJson
	if err := json.NewDecoder(r).Decode(&deps); err != nil {
		return nil, err
	}

	if filename != "" {
		deps.evidence = append(deps.evidence, filename)
	}

	return &deps, nil
}

// Root returns nil — deps.json does not contain a single root project entry.
func (d *depsJson) Root() *languages.Package {
	return nil
}

// Direct returns nil — deps.json does not distinguish direct from transitive.
func (d *depsJson) Direct() languages.Packages {
	return nil
}

// Transitive returns all NuGet package libraries (excludes project references).
func (d *depsJson) Transitive() languages.Packages {
	var packages languages.Packages
	for key, lib := range d.Libraries {
		if !lib.isPackage() {
			continue
		}

		// Key format is "Name/Version"
		name, version, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}

		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      version,
			Purl:         dotnet.NewPackageUrl(name, version),
			Cpes:         dotnet.NewCpes(name, version),
			EvidenceList: dotnet.NewEvidenceList(d.evidence),
		})
	}
	return packages
}
