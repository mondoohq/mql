// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package denolock parses Deno lockfiles (deno.lock) to extract the resolved
// npm and JSR package dependencies of a Deno project.
package denolock

import (
	"encoding/json"
	"io"
	"maps"
	"strings"

	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*denoLock)(nil)
)

// Extractor parses deno.lock files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "deno.lock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock denoLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}
	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}
	return &lock, nil
}

// denoLock models the parts of deno.lock that name resolved packages. The npm
// and jsr maps live at the top level in lockfile v4 and under `packages` in v3;
// both layouts are accepted.
type denoLock struct {
	Version  string               `json:"version"`
	Npm      map[string]denoEntry `json:"npm"`
	Jsr      map[string]denoEntry `json:"jsr"`
	Packages *denoPackages        `json:"packages"`

	evidence []string
}

type denoPackages struct {
	Npm map[string]denoEntry `json:"npm"`
	Jsr map[string]denoEntry `json:"jsr"`
}

type denoEntry struct {
	Integrity string `json:"integrity"`
}

// Root returns nil — a lockfile does not describe the root project.
func (l *denoLock) Root() *languages.Package { return nil }

// Direct returns nil — deno.lock does not distinguish direct from transitive.
func (l *denoLock) Direct() languages.Packages { return nil }

// Transitive returns every resolved npm and JSR package in the lockfile.
func (l *denoLock) Transitive() languages.Packages {
	var packages languages.Packages
	seen := map[string]bool{}

	add := func(pkg *languages.Package) {
		if pkg == nil || pkg.Name == "" || seen[pkg.Purl] {
			return
		}
		seen[pkg.Purl] = true
		packages = append(packages, pkg)
	}

	for key, entry := range l.mergedNpm() {
		add(l.npmPackage(key, entry))
	}
	for key, entry := range l.mergedJsr() {
		add(l.jsrPackage(key, entry))
	}
	return packages
}

// mergedNpm unions the top-level (v4) and nested (v3) npm maps.
func (l *denoLock) mergedNpm() map[string]denoEntry {
	out := map[string]denoEntry{}
	maps.Copy(out, l.Npm)
	if l.Packages != nil {
		maps.Copy(out, l.Packages.Npm)
	}
	return out
}

func (l *denoLock) mergedJsr() map[string]denoEntry {
	out := map[string]denoEntry{}
	maps.Copy(out, l.Jsr)
	if l.Packages != nil {
		maps.Copy(out, l.Packages.Jsr)
	}
	return out
}

// npmPackage builds a pkg:npm component from an npm lock key ("name@version",
// possibly scoped, possibly with a "_"-suffixed peer-dependency tag).
func (l *denoLock) npmPackage(key string, entry denoEntry) *languages.Package {
	name, version := splitNameVersion(key)
	if name == "" {
		return nil
	}
	return &languages.Package{
		Name:         name,
		Version:      version,
		Purl:         javascript.NewPackageUrl(name, version),
		Hashes:       javascript.NewHashes(entry.Integrity),
		EvidenceList: javascript.NewEvidenceList(l.evidence),
	}
}

// jsrPackage builds a component for a JSR ("@scope/name@version") package. JSR
// has no dedicated purl type; the convention is pkg:npm carrying a
// repository_url qualifier so it is not confused with an npm-registry package.
func (l *denoLock) jsrPackage(key string, entry denoEntry) *languages.Package {
	name, version := splitNameVersion(key)
	if name == "" {
		return nil
	}
	namespace := ""
	shortName := name
	if before, after, ok := strings.Cut(name, "/"); ok {
		namespace = before
		shortName = after
	}
	purl := packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		shortName,
		version,
		packageurl.QualifiersFromMap(map[string]string{"repository_url": "https://jsr.io"}),
		"",
	).String()
	return &languages.Package{
		Name:         name,
		Version:      version,
		Purl:         purl,
		Hashes:       javascript.NewHashes(entry.Integrity),
		EvidenceList: javascript.NewEvidenceList(l.evidence),
	}
}

// splitNameVersion splits a Deno lock key into package name and version. It
// strips any "_"-separated peer-dependency suffix Deno appends after the version
// ("chalk@5.3.0_supports-color@9.0.0" → chalk, 5.3.0) and splits name from
// version at the last "@" (so scoped "@babel/core@7.0.0" → @babel/core, 7.0.0).
func splitNameVersion(key string) (string, string) {
	if i := strings.IndexByte(key, '_'); i >= 0 {
		key = key[:i]
	}
	name, version, ok := strings.CutLast(key, "@")
	if !ok || name == "" { // no version, or leading-scope "@" only
		return key, ""
	}
	return name, version
}
