// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packpl

import (
	"bufio"
	"path"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/prolog"
)

// PrologPack represents a parsed SWI-Prolog pack.
type PrologPack struct {
	Name     string
	Version  string
	Title    string
	FilePath string
}

// termPattern matches Prolog terms like name(value). or name('value').
var termPattern = regexp.MustCompile(`^(\w+)\((?:'([^']*)'|(\w[^)]*?))\)\.`)

// ScanPackDir scans a directory for SWI-Prolog packs.
// Each subdirectory containing a pack.pl is treated as a pack.
func ScanPackDir(afs *afero.Afero, dir string) ([]PrologPack, error) {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		log.Debug().Err(err).Str("path", dir).Msg("mql[prolog]> could not read packs directory")
		return nil, nil
	}

	var packs []PrologPack
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		packPath := path.Join(dir, entry.Name(), "pack.pl")
		if exists, _ := afs.Exists(packPath); !exists {
			continue
		}

		pack, err := parsePackPl(afs, packPath)
		if err != nil {
			log.Debug().Err(err).Str("path", packPath).Msg("mql[prolog]> could not parse pack.pl")
			continue
		}
		if pack != nil {
			packs = append(packs, *pack)
		}
	}

	return packs, nil
}

// parsePackPl reads a pack.pl file and extracts name and version.
func parsePackPl(afs *afero.Afero, packPath string) (*PrologPack, error) {
	f, err := afs.Open(packPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pack := &PrologPack{FilePath: packPath}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		m := termPattern.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}

		key := m[1]
		// Value is either in group 2 (quoted) or group 3 (unquoted)
		value := m[2]
		if value == "" {
			value = m[3]
		}

		switch key {
		case "name":
			pack.Name = value
		case "version":
			pack.Version = value
		case "title":
			pack.Title = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if pack.Name == "" {
		return nil, nil
	}

	return pack, nil
}

// ToPackages converts a list of PrologPacks to language packages.
func ToPackages(packs []PrologPack) []*languages.Package {
	var packages []*languages.Package
	for _, p := range packs {
		packages = append(packages, &languages.Package{
			Name:         p.Name,
			Version:      p.Version,
			Purl:         prolog.NewPackageUrl(p.Name, p.Version),
			EvidenceList: prolog.NewEvidenceList([]string{p.FilePath}),
		})
	}
	return packages
}
