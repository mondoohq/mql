// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mixlock

import (
	"bufio"
	"errors"
	"io"
	"regexp"
	"strings"

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

	// mix.lock is a single Elixir map, %{ ... }; a file that does not close
	// it is truncated
	var first, last string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if first == "" {
				first = trimmed
			}
			last = trimmed
		}

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
	if first != "" && (!strings.HasPrefix(first, "%{") || !strings.HasSuffix(last, "}")) {
		return nil, errors.New("not a mix.lock map: it must open with %{ and close with }")
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
