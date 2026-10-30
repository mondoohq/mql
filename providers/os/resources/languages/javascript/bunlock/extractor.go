// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bunlock

import (
	"encoding/json"
	"io"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

// stripJSONC removes trailing commas before } and ] to convert JSONC to
// valid JSON. Bun.lock files use JSONC format (trailing commas allowed).
func stripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escape := false

	for i := range data {
		c := data[i]

		if escape {
			out = append(out, c)
			escape = false
			continue
		}

		if inString {
			out = append(out, c)
			switch c {
			case '\\':
				escape = true
			case '"':
				inString = false
			}
			continue
		}

		switch c {
		case '"':
			out = append(out, c)
			inString = true
		case ',':
			// Look ahead to see if the next non-whitespace is } or ].
			// If so, this is a trailing comma — skip it.
			trailing := false
			for j := i + 1; j < len(data); j++ {
				if data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r' {
					continue
				}
				if data[j] == '}' || data[j] == ']' {
					trailing = true
				}
				break
			}
			if !trailing {
				out = append(out, c)
			}
		default:
			out = append(out, c)
		}
	}
	return out
}

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*bunLock)(nil)
)

// Extractor parses bun.lock files to extract npm package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "bunlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	// bun.lock uses JSONC format (allows trailing commas).
	// Strip trailing commas before JSON decoding.
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	cleaned := stripJSONC(raw)

	var lock bunLock
	if err := json.Unmarshal(cleaned, &lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — bun.lock does not contain a root project entry in
// the packages section.
func (l *bunLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — bun.lock does not distinguish direct from transitive
// within the packages map without cross-referencing workspaces.
func (l *bunLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all packages listed in the lockfile.
func (l *bunLock) Transitive() languages.Packages {
	var packages languages.Packages

	for key, raw := range l.Packages {
		info, ok := parseBunPackageTuple(raw)
		if !ok {
			log.Warn().Str("key", key).Msg("cannot parse bun.lock package tuple")
			continue
		}

		packages = append(packages, &languages.Package{
			Name:         info.Name,
			Version:      info.Version,
			Purl:         javascript.NewPackageUrl(info.Name, info.Version),
			Cpes:         javascript.NewCpes(info.Name, info.Version),
			EvidenceList: javascript.NewEvidenceList(l.evidence),
		})
	}

	return packages
}
