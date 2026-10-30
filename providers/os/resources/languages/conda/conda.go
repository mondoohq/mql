// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package conda

import (
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
	"gopkg.in/yaml.v3"
)

// condaMetaPackage represents a single JSON file in conda-meta/.
type condaMetaPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Channel string `json:"channel"`
	Build   string `json:"build_string"`
}

// Extractor parses conda-meta directory or environment.yml files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "Conda Extractor"
}

// Parse handles environment.yml files (the lockfile-like format).
func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	pkgs, err := ParseEnvironmentYml(r, filename)
	if err != nil {
		return nil, err
	}
	return &condaBom{transitive: pkgs}, nil
}

// ParseCondaMeta scans a conda-meta directory and parses all JSON metadata files.
// Path: <env>/conda-meta/*.json
func ParseCondaMeta(afs *afero.Afero, condaMetaDir string) (languages.Packages, []string) {
	entries, err := afs.ReadDir(condaMetaDir)
	if err != nil {
		return nil, nil
	}

	var pkgs languages.Packages
	var filePaths []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// path.Join (not filepath.Join) — always Linux paths
		filePath := path.Join(condaMetaDir, entry.Name())
		f, err := afs.Open(filePath)
		if err != nil {
			continue
		}

		var meta condaMetaPackage
		err = json.NewDecoder(f).Decode(&meta)
		f.Close()
		if err != nil {
			log.Debug().Err(err).Str("path", filePath).Msg("mql[conda]> could not parse metadata")
			continue
		}

		if meta.Name == "" || meta.Version == "" {
			continue
		}

		pkgs = append(pkgs, &languages.Package{
			Name:    meta.Name,
			Version: meta.Version,
			Purl:    NewPackageUrl(meta.Name, meta.Version, meta.Channel),
			EvidenceList: []*sbom.Evidence{
				{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: filePath},
			},
		})
		filePaths = append(filePaths, filePath)
	}

	if len(pkgs) > 0 {
		log.Debug().Int("count", len(pkgs)).Str("dir", condaMetaDir).Msg("mql[conda]> found conda packages")
	}

	return pkgs, filePaths
}

// condaEnvironment represents a conda environment.yml file.
type condaEnvironment struct {
	Name         string `yaml:"name"`
	Dependencies []any  `yaml:"dependencies"`
}

// ParseEnvironmentYml parses a conda environment.yml file.
// It extracts conda package names and versions from the dependencies list.
// Nested sub-sections (e.g., pip dependencies) are skipped.
func ParseEnvironmentYml(r io.Reader, filename string) (languages.Packages, error) {
	var env condaEnvironment
	if err := yaml.NewDecoder(r).Decode(&env); err != nil {
		return nil, err
	}

	var pkgs languages.Packages
	for _, dep := range env.Dependencies {
		// String entries are conda packages (e.g., "numpy=1.26.4")
		// Map entries are nested sub-sections (e.g., pip: [...]) — skip them
		depStr, ok := dep.(string)
		if !ok {
			continue
		}

		name, version := parseCondaDep(depStr)
		if name == "" {
			continue
		}

		pkgs = append(pkgs, &languages.Package{
			Name:    name,
			Version: version,
			Purl:    NewPackageUrl(name, version, ""),
			EvidenceList: []*sbom.Evidence{
				{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: filename},
			},
		})
	}

	return pkgs, nil
}

// parseCondaDep parses a conda dependency string into name and version.
// Formats: "numpy=1.26.4=py312h5b0bcb5_0", "numpy=1.26.4", "numpy"
func parseCondaDep(dep string) (string, string) {
	parts := strings.SplitN(dep, "=", 3)
	name := strings.TrimSpace(parts[0])
	version := ""
	if len(parts) >= 2 {
		version = strings.TrimSpace(parts[1])
	}
	return name, version
}

// NewPackageUrl creates a Conda package URL.
// Format: pkg:conda/channel/name@version
func NewPackageUrl(name, version, channel string) string {
	if name == "" {
		return ""
	}
	// Normalize channel: extract just the channel name from URL
	ns := normalizeChannel(channel)
	return packageurl.NewPackageURL(
		"conda",
		ns,
		name,
		version,
		nil,
		"",
	).String()
}

// normalizeChannel extracts a short channel name from a conda channel URL.
// Example: "https://repo.anaconda.com/pkgs/main" → "pkgs/main"
func normalizeChannel(channel string) string {
	if channel == "" {
		return ""
	}
	// Strip common prefixes
	for _, prefix := range []string{
		"https://repo.anaconda.com/",
		"https://conda.anaconda.org/",
		"http://repo.anaconda.com/",
	} {
		if after, ok := strings.CutPrefix(channel, prefix); ok {
			return after
		}
	}
	return channel
}

type condaBom struct {
	transitive languages.Packages
}

func (b *condaBom) Root() *languages.Package       { return nil }
func (b *condaBom) Direct() languages.Packages     { return nil }
func (b *condaBom) Transitive() languages.Packages { return b.transitive }
