// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemfilelock

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/ruby"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*gemfileLock)(nil)
)

// Extractor parses Gemfile.lock files to extract Ruby gem dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "gemfilelock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	lock, err := parseGemfileLock(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return lock, nil
}

// parseGemfileLock reads a Gemfile.lock line by line and extracts gem entries.
func parseGemfileLock(r io.Reader) (*gemfileLock, error) {
	lock := &gemfileLock{
		DirectDeps: make(map[string]bool),
	}

	scanner := bufio.NewScanner(r)

	type section int
	const (
		sectionNone section = iota
		sectionGemSpecs
		sectionDependencies
		sectionBundledWith
	)

	currentSection := sectionNone
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()

		// Detect section headers (no leading whitespace)
		trimmed := strings.TrimSpace(line)

		// Section transitions
		switch trimmed {
		case "GEM":
			currentSection = sectionGemSpecs
			inSpecs = false
			continue
		case "PLATFORMS":
			currentSection = sectionNone
			continue
		case "DEPENDENCIES":
			currentSection = sectionDependencies
			continue
		case "BUNDLED WITH":
			currentSection = sectionBundledWith
			continue
		case "GIT", "PATH", "PLUGIN SOURCE":
			currentSection = sectionNone
			continue
		}

		switch currentSection {
		case sectionGemSpecs:
			if trimmed == "specs:" {
				inSpecs = true
				continue
			}
			if !inSpecs {
				continue
			}

			// Top-level gems are indented 4 spaces: "    name (version)".
			// Sub-dependencies are indented 6+ and belong to the gem above them.
			if !strings.HasPrefix(line, "    ") {
				continue
			}
			if strings.HasPrefix(line, "      ") {
				// A dependency line of the gem most recently appended. Bundler
				// always writes them directly beneath their gem, so the last
				// entry is the owner; a stray one before any gem has no owner
				// and is dropped rather than guessed at.
				if n := len(lock.Gems); n > 0 && trimmed != "" {
					if name := gemDepName(trimmed); name != "" {
						lock.Gems[n-1].Deps = append(lock.Gems[n-1].Deps, name)
					}
				}
				continue
			}

			entry := parseGemEntry(trimmed)
			if entry.Name != "" {
				lock.Gems = append(lock.Gems, entry)
			}

		case sectionDependencies:
			if trimmed == "" {
				continue
			}
			// Dependencies are "  name" or "  name (~> version)"
			// Extract just the name (first word)
			name := strings.Fields(trimmed)[0]
			// Remove trailing ! (used for platform-specific deps)
			name = strings.TrimSuffix(name, "!")
			lock.DirectDeps[name] = true

		case sectionBundledWith:
			if trimmed != "" {
				lock.BundledWith = trimmed
				currentSection = sectionNone
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lock, nil
}

// gemDepName takes the gem name from a dependency line beneath a spec entry,
// which is written as `rack` or `rack (~> 2.2)`. Only the name is kept: the
// parenthesised part is a REQUIREMENT, and the version Bundler actually resolved
// is on that gem's own spec entry, which is where dependsOnRefs looks it up.
func gemDepName(line string) string {
	name, _, _ := strings.Cut(line, " ")
	return strings.TrimSuffix(strings.TrimSpace(name), "!")
}

// dependsOnRefs turns one gem's dependency names into purls of the gems that
// satisfy them.
//
// Resolved by name against the same gem set this file emits, so an edge's target
// is always a package that exists. A name with no spec entry is dropped rather
// than synthesised: it means the lock referenced a gem it did not resolve here
// (a git or path source, which this extractor does not inventory), and inventing
// the node would assert a package the project does not install from RubyGems.
func dependsOnRefs(deps []string, byName map[string]gemEntry) []string {
	if len(deps) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for _, name := range deps {
		target, ok := byName[name]
		if !ok || target.Version == "" {
			continue
		}
		ref := ruby.NewPackageUrl(target.Name, target.Version)
		if seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil
	}
	sort.Strings(refs)
	return refs
}

// gemsByName indexes the resolved gems for edge resolution.
func (l *gemfileLock) gemsByName() map[string]gemEntry {
	out := make(map[string]gemEntry, len(l.Gems))
	for _, g := range l.Gems {
		if _, dup := out[g.Name]; !dup {
			out[g.Name] = g
		}
	}
	return out
}

// parseGemEntry parses "name (version)" or "name (version-platform)" from a GEM specs line.
func parseGemEntry(line string) gemEntry {
	// Format: "name (version)" or "name (version-platform)"
	openParen := strings.LastIndex(line, "(")
	closeParen := strings.LastIndex(line, ")")
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		return gemEntry{}
	}

	name := strings.TrimSpace(line[:openParen])
	version := line[openParen+1 : closeParen]

	// Strip platform suffix (e.g., "1.16.2-x86_64-linux" -> "1.16.2").
	// Match against known platform tokens to avoid stripping pre-release
	// suffixes like "1.0.0-beta1" (though Rubygems normally uses dots for those).
	if idx := strings.Index(version, "-"); idx != -1 {
		suffix := version[idx+1:]
		if isPlatformSuffix(suffix) {
			version = version[:idx]
		}
	}

	return gemEntry{Name: name, Version: version}
}

// knownPlatformTokens are substrings that identify a platform suffix in gem versions.
var knownPlatformTokens = []string{
	"x86_64", "x86", "aarch64", "arm64", "arm",
	"linux", "darwin", "mingw", "mswin", "java", "jruby",
	"musl", "freebsd", "openbsd",
}

// isPlatformSuffix returns true if the string contains a known platform identifier.
func isPlatformSuffix(s string) bool {
	lower := strings.ToLower(s)
	for _, token := range knownPlatformTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// Root returns nil — Gemfile.lock does not describe the root project.
func (l *gemfileLock) Root() *languages.Package {
	return nil
}

// Direct returns gems listed in the DEPENDENCIES section.
func (l *gemfileLock) Direct() languages.Packages {
	byName := l.gemsByName()
	var direct languages.Packages
	for _, gem := range l.Gems {
		if l.DirectDeps[gem.Name] {
			direct = append(direct, makePackage(gem, byName, l.evidence))
		}
	}
	return direct
}

// Transitive returns all resolved gems.
func (l *gemfileLock) Transitive() languages.Packages {
	byName := l.gemsByName()
	var all languages.Packages
	for _, gem := range l.Gems {
		all = append(all, makePackage(gem, byName, l.evidence))
	}
	return all
}

func makePackage(gem gemEntry, byName map[string]gemEntry, evidence []string) *languages.Package {
	return &languages.Package{
		Name:         gem.Name,
		Version:      gem.Version,
		Purl:         ruby.NewPackageUrl(gem.Name, gem.Version),
		Cpes:         ruby.NewCpes(gem.Name, gem.Version),
		EvidenceList: ruby.NewEvidenceList(evidence),
		DependsOn:    dependsOnRefs(gem.Deps, byName),
	}
}
