// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package composerjson

import (
	"encoding/json"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/php"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*composerJson)(nil)
)

// Extractor parses composer.json files to extract PHP project dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "composerjson"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var cj composerJson
	if err := json.NewDecoder(r).Decode(&cj); err != nil {
		return nil, err
	}

	if filename != "" {
		cj.evidence = append(cj.evidence, filename)
	}

	return &cj, nil
}

// Root returns the project itself as the root package.
func (cj *composerJson) Root() *languages.Package {
	if cj.Name == "" {
		return nil
	}

	return &languages.Package{
		Name:    cj.Name,
		Version: cj.Version,
		// The project's own license, which is a different question from the
		// licenses of what it requires. An array means a choice among them;
		// LicenseExpression renders that as SPDX.
		License:      languages.LicenseExpression(cj.License),
		Purl:         php.NewPackageUrl(cj.Name, cj.Version),
		Cpes:         php.NewCpes(cj.Name, cj.Version),
		EvidenceList: php.NewEvidenceList(cj.evidence),
	}
}

// Direct returns production dependencies (from "require", excluding php/ext-* entries).
func (cj *composerJson) Direct() languages.Packages {
	var direct languages.Packages
	for name, version := range cj.Require {
		if php.IsPhpExtensionOrPlatform(name) {
			continue
		}
		direct = append(direct, makePackage(name, version, cj.evidence))
	}
	return direct
}

// Transitive returns all declared dependencies (require + require-dev).
func (cj *composerJson) Transitive() languages.Packages {
	var all languages.Packages
	for name, version := range cj.Require {
		if php.IsPhpExtensionOrPlatform(name) {
			continue
		}
		all = append(all, makePackage(name, version, cj.evidence))
	}
	for name, version := range cj.RequireDev {
		if php.IsPhpExtensionOrPlatform(name) {
			continue
		}
		all = append(all, makePackage(name, version, cj.evidence))
	}
	return all
}

func makePackage(name, constraint string, evidence []string) *languages.Package {
	// composer.json contains version constraints (e.g., "^3.0", ">=8.1"), not
	// resolved versions. We include the constraint as-is for reference but only
	// generate PURL/CPE when it looks like an exact version (no constraint operators).
	pkg := &languages.Package{
		Name:         name,
		Version:      constraint,
		EvidenceList: php.NewEvidenceList(evidence),
	}

	if !isVersionConstraint(constraint) {
		pkg.Purl = php.NewPackageUrl(name, constraint)
		pkg.Cpes = php.NewCpes(name, constraint)
	}

	return pkg
}

// isVersionConstraint returns true if the string contains Composer constraint
// operators rather than being an exact version.
func isVersionConstraint(v string) bool {
	return strings.ContainsAny(v, "^~*><=|! ") || v == ""
}
