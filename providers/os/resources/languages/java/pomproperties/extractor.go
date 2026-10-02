// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pomproperties

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*pomProperties)(nil)
)

// Extractor parses Maven pom.properties files to extract package coordinates.
type Extractor struct {
	// EntryPath is the path of the pom.properties inside its archive, for
	// example META-INF/maven/org.lightcouch/lightcouch/pom.properties. When the
	// file has no groupId, the group is taken from this path.
	EntryPath string
}

func (e *Extractor) Name() string {
	return "pomproperties"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	props, err := parsePomProperties(r)
	if err != nil {
		return nil, err
	}

	if props.GroupId == "" {
		if groupId, artifactId, ok := coordinatesFromEntryPath(e.EntryPath); ok && artifactId == props.ArtifactId {
			props.GroupId = groupId
		}
	}

	if filename != "" {
		props.evidence = append(props.evidence, filename)
	}

	return props, nil
}

// coordinatesFromEntryPath returns the groupId and artifactId of a
// META-INF/maven/<groupId>/<artifactId>/pom.properties archive entry.
func coordinatesFromEntryPath(entryPath string) (string, string, bool) {
	parts := strings.Split(entryPath, "/")
	if len(parts) != 5 || parts[0] != "META-INF" || parts[1] != "maven" || parts[4] != "pom.properties" {
		return "", "", false
	}
	if parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// parsePomProperties reads a Java properties-format file and extracts
// groupId, artifactId, and version.
func parsePomProperties(r io.Reader) (*pomProperties, error) {
	props := &pomProperties{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Split on first = or :
		var key, value string
		if idx := strings.IndexAny(line, "=:"); idx != -1 {
			key = strings.TrimSpace(line[:idx])
			value = strings.TrimSpace(line[idx+1:])
		} else {
			continue
		}

		switch key {
		case "groupId":
			props.GroupId = value
		case "artifactId":
			props.ArtifactId = value
		case "version":
			props.Version = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return props, nil
}

// Root returns the package described by this pom.properties as the root.
func (p *pomProperties) Root() *languages.Package {
	if p.GroupId == "" && p.ArtifactId == "" {
		return nil
	}

	name := p.ArtifactId
	if p.GroupId != "" {
		name = p.GroupId + ":" + p.ArtifactId
	}

	return &languages.Package{
		Name:         name,
		Version:      p.Version,
		Purl:         java.NewPackageUrl(p.GroupId, p.ArtifactId, p.Version),
		Cpes:         java.NewCpes(p.GroupId, p.ArtifactId, p.Version),
		EvidenceList: java.NewEvidenceList(p.evidence),
	}
}

// Direct returns nil — pom.properties describes a single package, not dependencies.
func (p *pomProperties) Direct() languages.Packages {
	return nil
}

// Transitive returns the single package as a list for inclusion in the SBOM.
func (p *pomProperties) Transitive() languages.Packages {
	root := p.Root()
	if root == nil {
		return nil
	}
	return languages.Packages{root}
}
