// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package composerlock

import (
	"encoding/json"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/php"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*composerLock)(nil)
)

// Extractor parses composer.lock files to extract PHP/Composer dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "composerlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock composerLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — composer.lock does not describe the root project.
func (l *composerLock) Root() *languages.Package {
	return nil
}

// Direct returns production packages (from the "packages" section).
// Note: composer.lock does not distinguish direct from transitive — all resolved
// production deps appear in "packages". To identify truly direct dependencies,
// cross-reference with composer.json's "require" keys.
func (l *composerLock) Direct() languages.Packages {
	var direct languages.Packages
	for _, pkg := range l.Packages {
		direct = append(direct, makePackage(pkg, l.evidence, languages.PackageScopeProd))
	}
	return direct
}

// Transitive returns all packages: the "packages" section as production scope
// and "packages-dev" as development scope (composer.lock separates the two).
func (l *composerLock) Transitive() languages.Packages {
	var all languages.Packages
	for _, pkg := range l.Packages {
		all = append(all, makePackage(pkg, l.evidence, languages.PackageScopeProd))
	}
	for _, pkg := range l.PackagesDev {
		all = append(all, makePackage(pkg, l.evidence, languages.PackageScopeDev))
	}
	return all
}

func makePackage(pkg composerPackage, evidence []string, scope string) *languages.Package {
	return &languages.Package{
		Name:    pkg.Name,
		Version: pkg.Version,
		// composer.lock records the license as an array, which means a choice
		// among them; LicenseExpression renders that as SPDX.
		License:      languages.LicenseExpression(pkg.License),
		Description:  pkg.Description,
		Purl:         php.NewPackageUrl(pkg.Name, pkg.Version),
		Cpes:         php.NewCpes(pkg.Name, pkg.Version),
		EvidenceList: php.NewEvidenceList(evidence),
		Scope:        scope,
	}
}
