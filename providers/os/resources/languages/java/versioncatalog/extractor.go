// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versioncatalog

import (
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*catalog)(nil)
)

// Extractor parses a Gradle version catalog (gradle/libs.versions.toml).
//
// A catalog is where a modern Gradle project states its dependency coordinates;
// the build scripts then reference them by alias (`implementation(libs.okio)`).
// The alias names no coordinate, so a catalog-based project is invisible to a
// reader of the build scripts alone — measured on okhttp, 332 declarations
// yielded 7 coordinates, and on Signal-Android 562 yielded 4. The coordinates
// those aliases stand for are all here, spelled out.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "versioncatalog"
}

// catalog is the parsed TOML. Only [versions] and [libraries] are read:
// [bundles] lists aliases already covered here, and [plugins] names Gradle
// plugins by plugin id rather than by Maven coordinate.
type catalog struct {
	Versions  map[string]any `toml:"versions"`
	Libraries map[string]any `toml:"libraries"`

	evidence []string
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var c catalog
	if _, err := toml.NewDecoder(r).Decode(&c); err != nil {
		return nil, err
	}
	if filename != "" {
		c.evidence = append(c.evidence, filename)
	}
	return &c, nil
}

// Root returns nil — a catalog describes dependencies, not the project.
func (c *catalog) Root() *languages.Package { return nil }

// Direct returns the declared libraries. A catalog entry is a coordinate the
// project wrote down for itself, which is what direct means.
func (c *catalog) Direct() languages.Packages { return c.packages() }

// Transitive returns the same set: a catalog states coordinates, and resolving
// what those depend on needs Gradle.
func (c *catalog) Transitive() languages.Packages { return c.packages() }

func (c *catalog) packages() languages.Packages {
	// Map iteration order is random and the output feeds a rendered SBOM, so
	// the aliases are walked in a stable order.
	aliases := make([]string, 0, len(c.Libraries))
	for alias := range c.Libraries {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	var packages languages.Packages
	seen := map[string]bool{}
	for _, alias := range aliases {
		group, artifact, version, ok := c.library(c.Libraries[alias])
		if !ok {
			continue
		}
		name := group + ":" + artifact
		if key := name + "@" + version; seen[key] {
			continue
		} else {
			seen[key] = true
		}
		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      version,
			Purl:         java.NewPackageUrl(group, artifact, version),
			Cpes:         java.NewCpes(group, artifact, version),
			EvidenceList: java.NewEvidenceList(c.evidence),
		})
	}
	return packages
}

// library reads one [libraries] entry, in any of the spellings Gradle accepts:
// the "group:artifact:version" shorthand, a table with `module`, or a table
// with separate `group` and `name`.
func (c *catalog) library(v any) (group, artifact, version string, ok bool) {
	switch entry := v.(type) {
	case string:
		return splitModule(entry)
	case map[string]any:
		if m, isStr := entry["module"].(string); isStr {
			group, artifact, version, ok = splitModule(m)
			if !ok {
				return "", "", "", false
			}
		} else {
			group, _ = entry["group"].(string)
			artifact, _ = entry["name"].(string)
			if group == "" || artifact == "" {
				return "", "", "", false
			}
		}
		if v := c.version(entry["version"]); v != "" {
			version = v
		}
		return group, artifact, version, true
	}
	return "", "", "", false
}

// version resolves an entry's version: a literal, a `version.ref` into
// [versions], or a rich constraint ({ require = ... }).
func (c *catalog) version(v any) string {
	switch ver := v.(type) {
	case string:
		return java.ConcreteVersion(ver)
	case map[string]any:
		if ref, isStr := ver["ref"].(string); isStr {
			return c.resolveRef(ref)
		}
		return constraintVersion(ver)
	}
	return ""
}

// resolveRef looks an alias up in [versions], where the value is either a
// literal or a rich constraint.
func (c *catalog) resolveRef(ref string) string {
	switch v := c.Versions[ref].(type) {
	case string:
		return java.ConcreteVersion(v)
	case map[string]any:
		return constraintVersion(v)
	}
	return ""
}

// constraintVersion reads a rich version constraint. `require` and `prefer`
// state a version; `strictly` is preferred last because it is the one most
// often written as a range.
func constraintVersion(m map[string]any) string {
	for _, key := range []string{"require", "prefer", "strictly"} {
		if s, ok := m[key].(string); ok {
			if v := java.ConcreteVersion(s); v != "" {
				return v
			}
		}
	}
	return ""
}

// splitModule parses "group:artifact" or "group:artifact:version".
func splitModule(s string) (group, artifact, version string, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if len(parts) >= 3 {
		version = java.ConcreteVersion(parts[2])
	}
	return parts[0], parts[1], version, true
}
