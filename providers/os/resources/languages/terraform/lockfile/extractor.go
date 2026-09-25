// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lockfile

import (
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/terraform"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*terraformLock)(nil)
)

// Extractor parses .terraform.lock.hcl files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "terraform-lockfile"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	lock := parseTerraformLock(string(data))

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return lock, nil
}

var (
	// providerBlockRe matches the opening of a provider block. The body is
	// then delimited by brace counting rather than by the line ending, so a
	// single-line block is read as one block instead of running on into the
	// next one.
	providerBlockRe = regexp.MustCompile(`provider\s+"([^"]+)"\s*\{`)
	// attrRe pulls a quoted scalar attribute out of a block body. The name is
	// anchored on a word boundary so "constraints" is not read as "version".
	versionRe     = regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]*)"`)
	constraintsRe = regexp.MustCompile(`(?m)^\s*constraints\s*=\s*"([^"]*)"`)
	// hashesRe captures the contents of the hashes list.
	hashesRe = regexp.MustCompile(`(?s)hashes\s*=\s*\[(.*?)\]`)
	// hashEntryRe pulls each quoted hash out of that list.
	hashEntryRe = regexp.MustCompile(`"([^"]+)"`)
)

// parseTerraformLock reads a .terraform.lock.hcl file.
//
// The format is a restricted HCL that "terraform init" generates: a sequence of
// provider blocks, each holding a version, an optional constraints line and an
// optional list of hashes. Blocks are located by brace counting so that layout
// — one line or many — does not change what is read.
func parseTerraformLock(content string) *terraformLock {
	lock := &terraformLock{}

	content = stripComments(content)

	for _, loc := range providerBlockRe.FindAllStringSubmatchIndex(content, -1) {
		source := content[loc[2]:loc[3]]
		if source == "" {
			continue
		}

		// loc[1] is just past the opening brace.
		body, ok := blockBody(content, loc[1])
		if !ok {
			// Unterminated block: take what is left rather than dropping the
			// provider entirely, so a truncated file still reports what it
			// named.
			body = content[loc[1]:]
		}

		entry := providerEntry{Source: source}
		if m := versionRe.FindStringSubmatch(body); m != nil {
			entry.Version = m[1]
		}
		if m := constraintsRe.FindStringSubmatch(body); m != nil {
			entry.Constraints = m[1]
		}
		if m := hashesRe.FindStringSubmatch(body); m != nil {
			for _, h := range hashEntryRe.FindAllStringSubmatch(m[1], -1) {
				value := h[1]
				switch {
				case strings.HasPrefix(value, "zh:"):
					entry.ZipHashes = append(entry.ZipHashes, strings.TrimPrefix(value, "zh:"))
				case strings.HasPrefix(value, "h1:"):
					entry.DirHashes = append(entry.DirHashes, strings.TrimPrefix(value, "h1:"))
				}
			}
		}

		lock.Providers = append(lock.Providers, entry)
	}

	return lock
}

// blockBody returns the text between start and the brace that closes the block
// opened just before start. Quoted strings are skipped so a brace inside a
// value cannot end the block early.
func blockBody(content string, start int) (string, bool) {
	depth := 1
	inString := false
	for i := start; i < len(content); i++ {
		switch content[i] {
		case '\\':
			if inString {
				i++
			}
		case '"':
			inString = !inString
		case '{':
			if !inString {
				depth++
			}
		case '}':
			if !inString {
				depth--
				if depth == 0 {
					return content[start:i], true
				}
			}
		}
	}
	return "", false
}

// stripComments removes whole-line comments. Values in a lock file (source
// addresses, versions, hashes) never contain "#", but a generated file always
// opens with a two-line banner.
func stripComments(content string) string {
	lines := strings.Split(content, "\n")
	kept := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// Root returns nil — lock files don't have a root project.
func (l *terraformLock) Root() *languages.Package {
	return nil
}

// Direct returns nil. A lock file records the providers Terraform resolved but
// not which of them the configuration asked for by name; required_providers is
// where that is stated, and it lives in the .tf files.
func (l *terraformLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all locked providers.
func (l *terraformLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, p := range l.Providers {
		host, namespace, providerType := terraform.ParseProviderSource(p.Source)
		name := namespace + "/" + providerType
		if namespace == "" {
			name = providerType
		}

		pkg := &languages.Package{
			Name:    name,
			Type:    terraform.PackageTypeProvider,
			Version: p.Version,
			Purl:    terraform.NewPackageUrl(host, namespace, providerType, p.Version),
			// Origin carries the source address exactly as the lock file wrote
			// it. It is the only place the registry host survives: a private
			// registry shares its purl coordinate with the public one.
			Origin:       p.Source,
			EvidenceList: terraform.NewEvidenceList(l.evidence),
		}
		for _, h := range p.ZipHashes {
			pkg.Hashes = append(pkg.Hashes, languages.PackageHash{
				Alg:   "SHA-256",
				Value: h,
			})
		}

		packages = append(packages, pkg)
	}
	return packages
}
