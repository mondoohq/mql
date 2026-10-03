// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package opam parses OCaml opam files (*.opam and their *.opam.locked lock
// variants) to extract OCaml package dependencies.
package opam

import (
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

// Compiled once: applied to every opam file parsed.
var dependsHeader = regexp.MustCompile(`(?m)^depends:`)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*opamFile)(nil)
)

// Extractor parses opam package files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "opam"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	f, err := parseOpam(string(data))
	if err != nil {
		return nil, err
	}
	f.name = packageName(f.declaredName, filename)
	if filename != "" {
		f.evidence = append(f.evidence, filename)
	}
	return f, nil
}

// opamFile is the parsed view of an opam manifest: the package's own
// name/version plus its declared dependencies.
type opamFile struct {
	name         string // resolved package name (declared or filename-derived)
	declaredName string // value of the `name:` field, if any
	version      string // value of the `version:` field, if any
	deps         []opamDep
	evidence     []string
}

// opamDep is one entry of the `depends:` list.
type opamDep struct {
	name    string
	version string // pinned version from a `{= "x"}` formula (lock files); may be empty
	dev     bool   // true for {with-test}/{with-doc} deps (test/doc-only)
}

var (
	// A top-level `name:` / `version:` field with a quoted value.
	nameFieldRe    = regexp.MustCompile(`(?m)^name:\s*"([^"]+)"`)
	versionFieldRe = regexp.MustCompile(`(?m)^version:\s*"([^"]+)"`)
	// An exact-version constraint inside a dependency filter, e.g. {= "1.2.3"}.
	// The `=` must stand alone: anchored at the start of the filter or after a
	// separator, so the `=` in `>=`, `<=`, or `!=` is not mistaken for it.
	pinnedVersionRe = regexp.MustCompile(`(?:^|[\s&|(])=\s*"([^"]+)"`)
)

// parseOpam extracts the package name/version fields and the depends: list.
// A depends: list that never closes is a truncated file and an error.
func parseOpam(content string) (*opamFile, error) {
	content = stripComments(content)
	f := &opamFile{}
	if m := nameFieldRe.FindStringSubmatch(content); m != nil {
		f.declaredName = m[1]
	}
	if m := versionFieldRe.FindStringSubmatch(content); m != nil {
		f.version = m[1]
	}
	block, found, ok := dependsBlock(content)
	if found && !ok {
		return nil, errors.New("depends list is not closed")
	}
	if ok {
		f.deps = parseDepends(block)
	}
	return f, nil
}

// stripComments blanks out opam comments, a `#` to the end of its line and a
// `(* ... *)` block, which may nest. Quoted strings are left alone, so a `#`
// inside one stays. Every comment byte but a newline becomes a space, which
// keeps line starts where the field patterns expect them.
func stripComments(s string) string {
	b := []byte(s)
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		switch {
		case b[i] == '"':
			i = skipQuoted(s, i)
		case b[i] == '#':
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				end = len(s) - i
			}
			blank(i, i+end)
			i += end
		case b[i] == '(' && i+1 < len(b) && b[i+1] == '*':
			depth, j := 0, i
			for j < len(b) {
				if b[j] == '(' && j+1 < len(b) && b[j+1] == '*' {
					depth++
					j += 2
				} else if b[j] == '*' && j+1 < len(b) && b[j+1] == ')' {
					depth--
					j += 2
					if depth == 0 {
						break
					}
				} else {
					j++
				}
			}
			blank(i, j)
			i = j
		default:
			i++
		}
	}
	return string(b)
}

// dependsBlock returns the text inside the `depends: [ ... ]` list, whether
// the file has a depends: field, and whether its list closes. Bracket
// counting skips over quoted strings so a `[` or `]` byte inside a string
// literal does not throw off the depth.
func dependsBlock(content string) (string, bool, bool) {
	idx := dependsHeader.FindStringIndex(content)
	if idx == nil {
		return "", false, false
	}
	rest := content[idx[1]:]
	open := strings.IndexByte(rest, '[')
	if open < 0 {
		return "", false, false
	}
	depth := 0
	for i := open; i < len(rest); {
		switch rest[i] {
		case '"':
			i = skipQuoted(rest, i)
		case '[':
			depth++
			i++
		case ']':
			depth--
			if depth == 0 {
				return rest[open+1 : i], true, true
			}
			i++
		default:
			i++
		}
	}
	return "", true, false
}

// parseDepends tokenizes a depends block into dependencies. A quoted string is a
// dependency name; a following `{...}` filter (consumed whole and quote-aware,
// so braces or quotes inside it — like version strings — are never mistaken for
// structure) supplies the pinned version and test/doc scope. A `|` marks an
// opam disjunction ("a or b"): the first alternative is kept and the rest
// skipped, so a one-of group is not counted as several dependencies.
func parseDepends(block string) []opamDep {
	var deps []opamDep
	cur := -1
	skipAlternative := false
	for i := 0; i < len(block); {
		switch block[i] {
		case '"':
			end := skipQuoted(block, i)
			name := block[i+1 : end-1]
			if skipAlternative {
				// Second (or later) branch of a disjunction — ignore it.
				skipAlternative = false
				cur = -1
			} else {
				deps = append(deps, opamDep{name: name})
				cur = len(deps) - 1
			}
			i = end
		case '|':
			// Disjunction separator: drop the following alternative.
			skipAlternative = true
			i++
		case '{':
			end := skipFilter(block, i)
			filter := block[i+1 : end-1]
			if cur >= 0 {
				if m := pinnedVersionRe.FindStringSubmatch(filter); m != nil {
					deps[cur].version = m[1]
				}
				if strings.Contains(filter, "with-test") || strings.Contains(filter, "with-doc") {
					deps[cur].dev = true
				}
			}
			i = end
		default:
			i++
		}
	}
	return deps
}

// skipQuoted returns the index just past the closing quote of the double-quoted
// string starting at s[i] (i points at the opening quote). Backslash escapes are
// honored. If unterminated, it returns len(s).
func skipQuoted(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++ // skip the escaped byte
		case '"':
			return j + 1
		}
	}
	return len(s)
}

// skipFilter returns the index just past the closing brace of the `{...}` filter
// starting at s[i] (i points at the opening brace), tracking nested braces and
// skipping quoted strings so braces inside a string literal do not miscount.
func skipFilter(s string, i int) int {
	depth := 0
	for j := i; j < len(s); {
		switch s[j] {
		case '"':
			j = skipQuoted(s, j)
		case '{':
			depth++
			j++
		case '}':
			depth--
			if depth == 0 {
				return j + 1
			}
			j++
		default:
			j++
		}
	}
	return len(s)
}

// packageName resolves the package name: the declared `name:` field wins;
// otherwise it is derived from the filename (foo.opam / foo.opam.locked → foo).
func packageName(declared, filename string) string {
	if declared != "" {
		return declared
	}
	base := filepath.Base(filename)
	base = strings.TrimSuffix(base, ".locked")
	base = strings.TrimSuffix(base, ".opam")
	if base == "opam" || base == "." || base == "/" {
		// A bare `opam` file (no package prefix) does not name a package.
		return ""
	}
	return base
}

// Root returns the package the opam file itself describes.
func (f *opamFile) Root() *languages.Package {
	if f.name == "" {
		return nil
	}
	return &languages.Package{
		Name:         f.name,
		Version:      f.version,
		Purl:         newPackageURL(f.name, f.version),
		EvidenceList: newEvidenceList(f.evidence),
	}
}

// Direct returns the declared dependencies.
func (f *opamFile) Direct() languages.Packages {
	var packages languages.Packages
	for _, d := range f.deps {
		if d.name == "" {
			continue
		}
		scope := languages.PackageScopeProd
		if d.dev {
			scope = languages.PackageScopeDev
		}
		packages = append(packages, &languages.Package{
			Name:         d.name,
			Version:      d.version,
			Purl:         newPackageURL(d.name, d.version),
			EvidenceList: newEvidenceList(f.evidence),
			Scope:        scope,
		})
	}
	return packages
}

// Transitive returns nil — an opam file declares only direct dependencies.
func (f *opamFile) Transitive() languages.Packages {
	return nil
}

func newPackageURL(name, version string) string {
	return packageurl.NewPackageURL(packageurl.TypeOpam, "", name, version, nil, "").String()
}

func newEvidenceList(evidence []string) []*sbom.Evidence {
	list := make([]*sbom.Evidence, len(evidence))
	for i, e := range evidence {
		list[i] = &sbom.Evidence{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: e}
	}
	return list
}
