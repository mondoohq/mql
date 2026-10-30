// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package vcpkg parses vcpkg manifest files (vcpkg.json) to extract C/C++
// dependencies managed by Microsoft's vcpkg package manager.
package vcpkg

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/cpp"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*vcpkgManifest)(nil)
)

// Extractor parses vcpkg.json manifest files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "vcpkg"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var m vcpkgManifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, err
	}
	if filename != "" {
		m.evidence = append(m.evidence, filename)
	}
	return &m, nil
}

// vcpkgManifest is the subset of vcpkg.json the SBOM cares about. See
// https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json
type vcpkgManifest struct {
	Name string `json:"name"`
	// A vcpkg manifest carries at most one of these version fields for the port
	// itself; they are mutually exclusive by schema.
	Version       string `json:"version"`
	VersionSemver string `json:"version-semver"`
	VersionDate   string `json:"version-date"`
	VersionString string `json:"version-string"`

	Dependencies []vcpkgDependency       `json:"dependencies"`
	Overrides    []vcpkgOverride         `json:"overrides"`
	Features     map[string]vcpkgFeature `json:"features"`

	evidence []string
}

// vcpkgDependency is a manifest dependency, which vcpkg allows to be either a
// bare string ("fmt") or an object ({"name": "fmt", "version>=": "10.0.0"}).
type vcpkgDependency struct {
	Name string
	// MinVersion is the `version>=` floor. It is NOT the resolved version: the
	// registry baseline resolves the dependency, routinely to something higher.
	// Reported as a qualifier so the manifest's own constraint is visible
	// without claiming the project runs that version.
	MinVersion string
	// Host marks a build-time dependency — a tool that runs on the machine
	// doing the build rather than code linked into the artifact. It is vcpkg's
	// equivalent of a Conan tool_requires.
	Host bool
}

func (d *vcpkgDependency) UnmarshalJSON(b []byte) error {
	// Shorthand form: a bare string is the dependency name.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		d.Name = s
		return nil
	}
	var obj struct {
		Name       string `json:"name"`
		MinVersion string `json:"version>="`
		Host       bool   `json:"host"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("vcpkg dependency: expected string or object: %w", err)
	}
	d.Name = obj.Name
	d.MinVersion = obj.MinVersion
	d.Host = obj.Host
	return nil
}

// vcpkgFeature is one optional feature of a port. Its dependencies are only
// installed when the feature is selected, so they are real dependencies of the
// project whenever it builds that feature — and invisible otherwise.
type vcpkgFeature struct {
	Dependencies []vcpkgDependency `json:"dependencies"`
}

// vcpkgOverride pins a dependency to an exact version, the one place a manifest
// states concrete versions (dependency versions otherwise come from the
// registry baseline, which is not resolvable offline).
type vcpkgOverride struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// rootVersion returns the port's own version from whichever version field is set.
func (m *vcpkgManifest) rootVersion() string {
	switch {
	case m.Version != "":
		return m.Version
	case m.VersionSemver != "":
		return m.VersionSemver
	case m.VersionDate != "":
		return m.VersionDate
	default:
		return m.VersionString
	}
}

// Root returns the manifest's own port as the project package. It is not a
// dependency, so SBOM generation does not list it as a component.
func (m *vcpkgManifest) Root() *languages.Package {
	if m.Name == "" {
		return nil
	}
	v := m.rootVersion()
	return &languages.Package{
		Name:         m.Name,
		Version:      v,
		Purl:         cpp.NewVcpkgPackageUrl(m.Name, v),
		EvidenceList: cpp.NewEvidenceList(m.evidence),
	}
}

// Direct returns the declared dependencies, with any override-pinned version
// applied. A dependency without an override has no manifest-stated version (it
// resolves through the registry baseline), so its version is left empty rather
// than filled from the `version>=` floor — a floor is a minimum, and the
// baseline routinely resolves above it.
//
// Feature dependencies are included. A feature's dependencies are conditional
// on the feature being selected, which this file cannot know; omitting them
// hides a real dependency of any build that selects the feature, while
// including one an unselected build does not use costs an unreachable component
// in the report. Only one of those loses a vulnerability.
func (m *vcpkgManifest) Direct() languages.Packages {
	overrides := make(map[string]string, len(m.Overrides))
	for _, o := range m.Overrides {
		if o.Name != "" {
			overrides[o.Name] = o.Version
		}
	}

	seen := make(map[string]bool, len(m.Dependencies))
	var packages languages.Packages

	add := func(deps []vcpkgDependency) {
		for _, dep := range deps {
			if dep.Name == "" || seen[dep.Name] {
				continue
			}
			seen[dep.Name] = true

			qualifiers := map[string]string{}
			version := overrides[dep.Name]
			// The floor is only worth stating where it is the sole constraint;
			// an override has already pinned an exact version.
			if version == "" && dep.MinVersion != "" {
				qualifiers["version_min"] = dep.MinVersion
			}

			scope := languages.PackageScopeProd
			if dep.Host {
				scope = languages.PackageScopeDev
			}

			packages = append(packages, &languages.Package{
				Name:         dep.Name,
				Version:      version,
				Purl:         cpp.NewVcpkgPackageUrlWithQualifiers(dep.Name, version, qualifiers),
				EvidenceList: cpp.NewEvidenceList(m.evidence),
				Scope:        scope,
			})
		}
	}

	add(m.Dependencies)

	// Deterministic order: features are a JSON object, and ranging the map
	// would reorder the SBOM between runs of the same scan.
	names := make([]string, 0, len(m.Features))
	for name := range m.Features {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add(m.Features[name].Dependencies)
	}

	return packages
}

// Transitive returns nil — vcpkg.json declares only direct dependencies; the
// full resolved set lives in the registry baseline, not the manifest.
func (m *vcpkgManifest) Transitive() languages.Packages {
	return nil
}
