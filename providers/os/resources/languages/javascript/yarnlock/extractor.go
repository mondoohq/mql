// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yarnlock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
	"sigs.k8s.io/yaml"
)

// Compiled once: matched against every line of a yarn.lock file.
var kv = regexp.MustCompile(`^(\s+)(\S+)\s+(.+?)\s*$`)

// yarnLockBom wraps a parsed yarnLock with file evidence.
type yarnLockBom struct {
	packages yarnLock
	evidence []string
}

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*yarnLockBom)(nil)
)

type Extractor struct{}

func (p *Extractor) Name() string {
	return "yarnlock"
}

func (p *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// yarn berry (v2+) lockfiles are already YAML and carry a top-level
	// __metadata entry; only the classic v1 format needs converting.
	if !isBerryLock(data) {
		data, err = classicToYAML(data)
		if err != nil {
			return nil, err
		}
	}

	var lock yarnLock

	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var result yarnLockBom
	result.packages = lock
	if filename != "" {
		result.evidence = append(result.evidence, filename)
	}

	return &result, nil
}

// berryMetadata matches the top-level __metadata key every yarn berry (v2+)
// lockfile starts with.
var berryMetadata = regexp.MustCompile(`(?m)^__metadata:\s*$`)

func isBerryLock(data []byte) bool {
	return berryMetadata.Match(data)
}

// classicToYAML converts the yarn.lock v1 (classic) pseudo-YAML to real YAML.
//
// Entry headers list every spec the entry answers, comma separated, and quote
// only the specs that need it: `"statuses@>= 1.5.0 < 2", statuses@~1.5.0:`.
// That is not a YAML key, so each header is rewritten as one double-quoted key
// with the specs unquoted (`"statuses@>= 1.5.0 < 2, statuses@~1.5.0":`), the
// form specIndex splits on commas.
//
// Indented entries are written as `key value` (space-separated), not
// `key: value`, and the value may be quoted (`version "1.3.8"`) or unquoted
// (`integrity sha512-…`). Both forms become `key: "value"`. Blank lines,
// comments and nested mapping headers (`dependencies:`) pass through.
func classicToYAML(data []byte) ([]byte, error) {
	var b bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// yarn.lock integrity/resolved lines can be long; grow the scanner buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			b.WriteString(line + "\n")
			continue
		}
		if line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(trimmed, ":") {
			b.WriteString(classicHeaderKey(strings.TrimSuffix(trimmed, ":")) + ":\n")
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			b.WriteString(line + "\n")
			continue
		}
		if m := kv.FindStringSubmatch(line); m != nil {
			val := m[3]
			if !strings.HasPrefix(val, `"`) || !strings.HasSuffix(val, `"`) {
				val = `"` + val + `"`
			}
			b.WriteString(m[1] + m[2] + ": " + val + "\n")
			continue
		}
		b.WriteString(line + "\n")
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// classicHeaderKey turns a classic entry header (without its trailing colon)
// into one YAML double-quoted key holding the comma-separated, unquoted specs.
func classicHeaderKey(header string) string {
	specs := strings.Split(header, ",")
	for i := range specs {
		specs[i] = strings.Trim(strings.TrimSpace(specs[i]), `"`)
	}
	// a JSON string is a valid YAML double-quoted scalar
	key, _ := json.Marshal(strings.Join(specs, ", "))
	return string(key)
}

func (p *yarnLockBom) Root() *languages.Package {
	// we don't have a root package in yarn.lock
	return nil
}

func (p *yarnLockBom) Direct() languages.Packages {
	return nil
}

func (p *yarnLockBom) Transitive() languages.Packages {
	var transitive languages.Packages
	idx := p.packages.specIndex()

	// add all dependencies
	for k, v := range p.packages {
		// berry bookkeeping, and the project's own workspaces (local source
		// with the placeholder version 0.0.0-use.local), are not installed
		// packages
		if k == "__metadata" || strings.Contains(k, "@workspace:") {
			continue
		}
		name, _, err := parseYarnPackageName(k)
		if err != nil {
			log.Error().Str("name", name).Msg("cannot parse yarn package name")
			continue
		}
		transitive = append(transitive, &languages.Package{
			Name:         name,
			Version:      v.Version,
			Purl:         javascript.NewPackageUrl(name, v.Version),
			Cpes:         javascript.NewCpes(name, v.Version),
			EvidenceList: javascript.NewEvidenceList(p.evidence),
			DependsOn:    dependsOnRefs(idx, v.Dependencies),
			Hashes:       javascript.NewHashes(v.Integrity),
		})
	}

	return transitive
}
