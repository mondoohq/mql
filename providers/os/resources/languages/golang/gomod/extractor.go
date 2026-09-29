// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gomod

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/golang"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*goMod)(nil)
)

// Extractor parses go.mod files to extract Go module dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "gomod"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	mod, err := parseGoMod(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		mod.evidence = append(mod.evidence, filename)
	}

	return mod, nil
}

// parseGoMod parses a go.mod file from a reader.
func parseGoMod(r io.Reader) (*goMod, error) {
	mod := &goMod{
		Replace: make(map[string]goModRequire),
	}

	scanner := bufio.NewScanner(r)
	inRequireBlock := false
	inReplaceBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle block closings
		if line == ")" {
			inRequireBlock = false
			inReplaceBlock = false
			continue
		}

		// Handle block openings (tolerant of extra whitespace)
		if strings.HasPrefix(line, "require") && strings.HasSuffix(line, "(") {
			inRequireBlock = true
			continue
		}
		if strings.HasPrefix(line, "replace") && strings.HasSuffix(line, "(") {
			inReplaceBlock = true
			continue
		}

		// Inside a require block
		if inRequireBlock {
			req := parseRequireLine(line)
			if req.Path != "" {
				mod.Require = append(mod.Require, req)
			}
			continue
		}

		// Inside a replace block
		if inReplaceBlock {
			parseReplaceLine(line, mod)
			continue
		}

		// Single-line directives
		if val, ok := strings.CutPrefix(line, "module "); ok {
			mod.Module = val
			continue
		}

		if val, ok := strings.CutPrefix(line, "go "); ok {
			mod.GoVersion = val
			continue
		}

		// Single-line require
		if val, ok := strings.CutPrefix(line, "require "); ok {
			req := parseRequireLine(val)
			if req.Path != "" {
				mod.Require = append(mod.Require, req)
			}
			continue
		}

		// Single-line replace
		if val, ok := strings.CutPrefix(line, "replace "); ok {
			parseReplaceLine(val, mod)
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return mod, nil
}

// parseRequireLine parses a single require entry like "github.com/pkg/errors v0.9.1 // indirect"
func parseRequireLine(line string) goModRequire {
	// Remove inline comments but detect // indirect first
	indirect := strings.Contains(line, "// indirect")

	// Remove comment portion
	if idx := strings.Index(line, "//"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return goModRequire{}
	}

	return goModRequire{
		Path:     parts[0],
		Version:  parts[1],
		Indirect: indirect,
	}
}

// parseReplaceLine parses a replace directive like "github.com/foo/bar v1.0.0 => github.com/foo/bar v1.1.0"
func parseReplaceLine(line string, mod *goMod) {
	parts := strings.Split(line, "=>")
	if len(parts) != 2 {
		return
	}

	original := strings.Fields(strings.TrimSpace(parts[0]))
	replacement := strings.Fields(strings.TrimSpace(parts[1]))

	if len(original) < 1 || len(replacement) < 1 {
		return
	}

	origPath := original[0]

	repReq := goModRequire{
		Path: replacement[0],
	}
	if len(replacement) >= 2 {
		repReq.Version = replacement[1]
	}

	mod.Replace[origPath] = repReq
}

// Root returns the root module as a Package.
func (m *goMod) Root() *languages.Package {
	if m.Module == "" {
		return nil
	}

	return &languages.Package{
		Name:         m.Module,
		Version:      "",
		Purl:         golang.NewPackageUrl(m.Module, ""),
		Cpes:         golang.NewCpes(m.Module, ""),
		EvidenceList: golang.NewEvidenceList(m.evidence),
	}
}

// Direct returns direct dependencies (those not marked as indirect).
func (m *goMod) Direct() languages.Packages {
	var direct languages.Packages
	for _, req := range m.Require {
		if req.Indirect {
			continue
		}
		path, version := m.resolveReplace(req.Path, req.Version)
		direct = append(direct, &languages.Package{
			Name:         path,
			Version:      version,
			Purl:         golang.NewPackageUrl(path, version),
			Cpes:         golang.NewCpes(path, version),
			EvidenceList: golang.NewEvidenceList(m.evidence),
		})
	}
	return direct
}

// Transitive returns all dependencies (both direct and indirect).
func (m *goMod) Transitive() languages.Packages {
	var all languages.Packages
	for _, req := range m.Require {
		path, version := m.resolveReplace(req.Path, req.Version)
		all = append(all, &languages.Package{
			Name:         path,
			Version:      version,
			Purl:         golang.NewPackageUrl(path, version),
			Cpes:         golang.NewCpes(path, version),
			EvidenceList: golang.NewEvidenceList(m.evidence),
		})
	}
	return all
}

// resolveReplace checks if a module has a replace directive and returns the
// replacement's module path and version.
//
// A replacement WITH a version is a MODULE replacement (a fork or a version
// bump): `rep.Path` is a module path and correctly names the package.
//
// A replacement WITHOUT a version is a LOCAL/filesystem replacement
// (`=> ./staging/apimachinery`, `=> ../foo`): per the go.mod grammar a
// directory replacement never carries a version, so `rep.Path` is a filesystem
// path, not a module path. It must NOT become the package name/purl — a package
// keyed on `../apimachinery` instead of `k8s.io/apimachinery` cannot be matched
// against advisories. Keep the ORIGINAL module path (and its declared version);
// the local source is in-tree, so the original identifier is the right one.
func (m *goMod) resolveReplace(path, version string) (string, string) {
	if rep, ok := m.Replace[path]; ok && rep.Version != "" {
		return rep.Path, rep.Version
	}
	return path, version
}
