// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifestmf

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*manifest)(nil)
)

// Extractor parses META-INF/MANIFEST.MF files to extract package metadata.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "manifestmf"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	m, err := parseManifest(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		m.evidence = append(m.evidence, filename)
	}

	return m, nil
}

// parseManifest reads a MANIFEST.MF file, handling continuation lines
// (lines starting with a single space are appended to the previous header value).
func parseManifest(r io.Reader) (*manifest, error) {
	m := &manifest{
		Headers: make(map[string]string),
	}

	scanner := bufio.NewScanner(r)
	var lastKey string

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line separates main section from individual sections.
		// We only care about the main section.
		if line == "" {
			break
		}

		// Continuation line: starts with a single space
		if strings.HasPrefix(line, " ") && lastKey != "" {
			m.Headers[lastKey] += strings.TrimPrefix(line, " ")
			continue
		}

		// Header line: "Name: Value"
		if key, value, ok := strings.Cut(line, ": "); ok {
			m.Headers[key] = value
			lastKey = key
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return m, nil
}

// name returns the best package name from the manifest headers.
// Prefers Bundle-SymbolicName (OSGi), falls back to Implementation-Title.
func (m *manifest) name() string {
	if name := m.Headers[headerBundleSymbolicName]; name != "" {
		return name
	}
	return m.Headers[headerImplementationTitle]
}

// version returns the best version from the manifest headers.
// Prefers Bundle-Version, falls back to Implementation-Version.
func (m *manifest) version() string {
	if ver := m.Headers[headerBundleVersion]; ver != "" {
		return ver
	}
	return m.Headers[headerImplementationVersion]
}

// vendor returns the vendor from the manifest headers.
func (m *manifest) vendor() string {
	if v := m.Headers[headerBundleVendor]; v != "" {
		return v
	}
	return m.Headers[headerImplementationVendor]
}

// Root returns the package described by this manifest.
func (m *manifest) Root() *languages.Package {
	name := m.name()
	version := m.version()

	if name == "" {
		return nil
	}

	// For MANIFEST.MF, we don't have groupId, so use name as both namespace and name
	// in the PURL. This is a fallback — pom.properties is preferred when available.
	pkg := &languages.Package{
		Name:         name,
		Version:      version,
		Purl:         java.NewPackageUrl("", name, version),
		Cpes:         java.NewCpes("", name, version),
		EvidenceList: java.NewEvidenceList(m.evidence),
	}

	if v := m.vendor(); v != "" {
		pkg.Vendor = v
	}

	if l := m.license(); l != "" {
		pkg.License = l
	}

	return pkg
}

// Direct returns nil — MANIFEST.MF describes a single package.
func (m *manifest) Direct() languages.Packages {
	return nil
}

// Transitive returns the single package.
func (m *manifest) Transitive() languages.Packages {
	root := m.Root()
	if root == nil {
		return nil
	}
	return languages.Packages{root}
}
