// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemspec

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/v13/providers/os/resources/languages"
	"go.mondoo.com/mql/v13/providers/os/resources/languages/ruby"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*gemSpec)(nil)
)

// Patterns for extracting gemspec metadata via static analysis.
// These match common patterns without executing Ruby.
var (
	// spec.name = "foo" or spec.name = 'foo'
	namePattern = regexp.MustCompile(`\.name\s*=\s*["']([^"']+)["']`)
	// spec.version = "1.0.0" or spec.version = '1.0.0'
	versionPattern = regexp.MustCompile(`\.version\s*=\s*["']([^"']+)["']`)
	// spec.license = "Apache-2.0" — the singular form. A gemspec may state its
	// license either way, and the two are the same field: RubyGems' `license=`
	// is a one-element `licenses=`.
	licensePattern = regexp.MustCompile(`\.license\s*=\s*["']([^"']*)["']`)
	// spec.licenses = ["MIT", "Apache-2.0"] — the plural form, a list. Matching
	// is line-scoped like every other pattern here, so a list broken across
	// source lines is not read; gemspecs write this one on a single line.
	licensesPattern = regexp.MustCompile(`\.licenses\s*=\s*\[([^\]]*)\]`)
	// the quoted members of that list
	quotedStringPattern = regexp.MustCompile(`["']([^"']*)["']`)
	// spec.add_dependency "foo", "~> 1.0"
	// spec.add_runtime_dependency "foo", "~> 1.0"
	// spec.add_development_dependency "foo", "~> 1.0"
	depPattern = regexp.MustCompile(`\.(add_dependency|add_runtime_dependency|add_development_dependency)\s+["']([^"']+)["'](?:,\s*["']([^"']+)["'])?`)
)

// Extractor parses .gemspec files to extract gem metadata via static analysis.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "gemspec"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	spec, err := parseGemspec(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		spec.evidence = append(spec.evidence, filename)
	}

	return spec, nil
}

// parseGemspec reads a .gemspec file and extracts metadata via regex matching.
// This is static analysis — it does not execute Ruby code.
func parseGemspec(r io.Reader) (*gemSpec, error) {
	spec := &gemSpec{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// A commented-out line states nothing. Reading one is how a gemspec
		// that commented its license out while changing it gets reported under
		// the old one, and a wrong license is worse than none: a consumer
		// cannot tell it from a license the gem actually declares. The same
		// applies to a commented-out name or version.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if m := namePattern.FindStringSubmatch(line); len(m) > 1 {
			spec.Name = m[1]
		}

		if m := versionPattern.FindStringSubmatch(line); len(m) > 1 {
			spec.Version = m[1]
		}

		// Both license forms write the same field, so the last one the file
		// states wins — which is what Ruby does when a gemspec sets both.
		if m := licensePattern.FindStringSubmatch(line); len(m) > 1 {
			spec.Licenses = []string{m[1]}
		}

		if m := licensesPattern.FindStringSubmatch(line); len(m) > 1 {
			var licenses []string
			for _, q := range quotedStringPattern.FindAllStringSubmatch(m[1], -1) {
				licenses = append(licenses, q[1])
			}
			spec.Licenses = licenses
		}

		if m := depPattern.FindStringSubmatch(line); len(m) > 2 {
			depType := m[1]
			depName := m[2]
			constraint := ""
			if len(m) > 3 {
				constraint = m[3]
			}

			spec.Dependencies = append(spec.Dependencies, gemDep{
				Name:       depName,
				Constraint: constraint,
				IsDev:      depType == "add_development_dependency",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return spec, nil
}

// Root returns the gem itself as the root package.
func (s *gemSpec) Root() *languages.Package {
	if s.Name == "" {
		return nil
	}

	return &languages.Package{
		Name:    s.Name,
		Version: s.Version,
		// A gemspec listing several licenses offers a choice among them, which
		// is SPDX's OR. Values are passed through as the gemspec wrote them.
		License:      languages.LicenseExpression(s.Licenses),
		Purl:         ruby.NewPackageUrl(s.Name, s.Version),
		Cpes:         ruby.NewCpes(s.Name, s.Version),
		EvidenceList: ruby.NewEvidenceList(s.evidence),
	}
}

// Direct returns non-dev dependencies.
func (s *gemSpec) Direct() languages.Packages {
	var direct languages.Packages
	for _, dep := range s.Dependencies {
		if dep.IsDev {
			continue
		}
		direct = append(direct, makeDepPackage(dep, s.evidence))
	}
	return direct
}

// Transitive returns all declared dependencies (gemspec only has direct deps).
func (s *gemSpec) Transitive() languages.Packages {
	var all languages.Packages
	for _, dep := range s.Dependencies {
		all = append(all, makeDepPackage(dep, s.evidence))
	}
	return all
}

func makeDepPackage(dep gemDep, evidence []string) *languages.Package {
	// Always generate a PURL — version is optional per the PURL spec.
	// Exact pins ("= 1.2.3") get a versioned PURL; constraints get versionless.
	version := dep.Constraint
	purlVersion := ""
	if !isVersionConstraint(dep.Constraint) {
		purlVersion = extractPinnedVersion(dep.Constraint)
	}

	return &languages.Package{
		Name:         dep.Name,
		Version:      version,
		Purl:         ruby.NewPackageUrl(dep.Name, purlVersion),
		Cpes:         ruby.NewCpes(dep.Name, purlVersion),
		EvidenceList: ruby.NewEvidenceList(evidence),
	}
}

// isVersionConstraint returns true if the string is a version constraint
// rather than an exact version. Exact pins like "= 1.2.3" are NOT constraints
// — they resolve to a specific version.
func isVersionConstraint(v string) bool {
	if v == "" {
		return true
	}
	// Exact pin: "= 1.2.3" (single = followed by space and version)
	if strings.HasPrefix(v, "= ") {
		return false
	}
	return strings.ContainsAny(v, "~><=! ")
}

// extractPinnedVersion extracts the version from an exact pin constraint "= X.Y.Z".
func extractPinnedVersion(v string) string {
	if strings.HasPrefix(v, "= ") {
		return strings.TrimPrefix(v, "= ")
	}
	return v
}
