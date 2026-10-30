// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mixlock

import (
	"bufio"
	"io"
	"regexp"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/hex"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*mixLock)(nil)
)

// mixLockPattern matches Elixir mix.lock entries:
// "name": {:hex, :name, "version", ...}
var mixLockPattern = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"`)

// Extractor parses Elixir mix.lock files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "mixlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	lock := &mixLock{}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		m := mixLockPattern.FindStringSubmatch(line)
		if len(m) == 3 {
			lock.Packages = append(lock.Packages, mixPackage{
				Name:    m[1],
				Version: m[2],
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lock, nil
}

// Root returns nil — mix.lock does not describe the root project.
func (l *mixLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — mix.lock does not distinguish direct from transitive.
func (l *mixLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all resolved packages.
func (l *mixLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pkg := range l.Packages {
		packages = append(packages, &languages.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Purl:         hex.NewPackageUrl(pkg.Name, pkg.Version),
			EvidenceList: hex.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
