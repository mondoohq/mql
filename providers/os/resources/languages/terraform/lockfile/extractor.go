// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lockfile

import (
	"bufio"
	"fmt"
	"io"
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
	lock, err := parseTerraformLock(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return lock, nil
}

// parseTerraformLock reads a .terraform.lock.hcl file line by line.
// The format is a simplified HCL with provider blocks containing version fields.
func parseTerraformLock(r io.Reader) (*terraformLock, error) {
	lock := &terraformLock{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var currentSource string
	var currentVersion string
	braceDepth := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Detect provider block opening: provider "source" {
		if strings.HasPrefix(line, "provider ") && strings.HasSuffix(line, "{") {
			source := extractQuotedString(line)
			if source != "" {
				currentSource = source
				currentVersion = ""
				braceDepth = 1
			}
			continue
		}

		// terraform writes nothing but provider blocks
		if braceDepth == 0 {
			return nil, fmt.Errorf("unexpected line outside a provider block: %q", line)
		}

		// Track brace depth for nested blocks (e.g., hashes)
		if braceDepth > 0 {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			// Extract version from within the provider block.
			// Match "version", "version ", "version=" but not e.g. "version_constraints".
			if line == "version" || strings.HasPrefix(line, "version ") || strings.HasPrefix(line, "version=") {
				if v := extractHCLValue(line); v != "" {
					currentVersion = v
				}
			}

			// Block closed — emit provider entry
			if braceDepth == 0 && currentSource != "" {
				lock.Providers = append(lock.Providers, providerEntry{
					Source:  currentSource,
					Version: currentVersion,
				})
				currentSource = ""
				currentVersion = ""
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// a provider block still open at the end is a truncated lock file
	if currentSource != "" {
		return nil, fmt.Errorf("provider %q block is not closed", currentSource)
	}

	return lock, nil
}

// extractQuotedString extracts the first double-quoted string from a line.
// e.g., `provider "registry.terraform.io/hashicorp/aws" {` → `registry.terraform.io/hashicorp/aws`
func extractQuotedString(line string) string {
	first := strings.Index(line, "\"")
	if first == -1 {
		return ""
	}
	second := strings.Index(line[first+1:], "\"")
	if second == -1 {
		return ""
	}
	return line[first+1 : first+1+second]
}

// extractHCLValue extracts the value from a simple HCL assignment like `version = "5.31.0"`.
func extractHCLValue(line string) string {
	_, value, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	// Strip quotes
	value = strings.Trim(value, "\"")
	return value
}

// Root returns nil — lock files don't have a root project.
func (l *terraformLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — all providers are treated equally.
func (l *terraformLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all locked providers.
func (l *terraformLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, p := range l.Providers {
		namespace, providerType := terraform.ParseProviderSource(p.Source)
		name := namespace + "/" + providerType
		if namespace == "" {
			name = providerType
		}

		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      p.Version,
			Purl:         terraform.NewPackageUrl(namespace, providerType, p.Version),
			Cpes:         terraform.NewCpes(namespace, providerType, p.Version),
			EvidenceList: terraform.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
