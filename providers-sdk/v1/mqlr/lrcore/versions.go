// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// LrVersions maps an LR path (resource or resource.field) to its min_provider_version.
type LrVersions map[string]string

// ReadVersions parses a .lr.versions file. Blank lines and lines starting with # are ignored.
// Each data line has the format: <path> <version>
func ReadVersions(path string) (LrVersions, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	versions := LrVersions{}
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: expected 2 fields, got %d", path, lineNum, len(fields))
		}
		versions[fields[0]] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return versions, nil
}

// WriteVersions writes a .lr.versions file sorted alphabetically by path.
// An optional headerTpl is used for a license header (using # as line prefix).
func WriteVersions(path string, versions LrVersions, headerTpl *template.Template) error {
	var sb strings.Builder

	header, err := LicenseHeader(headerTpl, LicenseHeaderOptions{LineStarter: "#"})
	if err != nil {
		return fmt.Errorf("could not generate license header: %w", err)
	}
	sb.WriteString(header)

	keys := make([]string, 0, len(versions))
	for k := range versions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Fprintf(&sb, "%s %s\n", k, versions[k])
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// InjectVersions sets MinProviderVersion on resources and fields in the schema
// based on the versions map. Fields whose version matches the parent resource
// are left empty (omitted from JSON via omitempty), since consumers treat an
// unset field version as equal to the resource version.
func InjectVersions(schema *resources.Schema, versions LrVersions) {
	// Build a sorted list of resource names (longest first) so we can
	// disambiguate field paths like "aws.ec2.instance.tags" where the resource
	// is "aws.ec2.instance" and the field is "tags".
	resourceNames := make([]string, 0, len(schema.Resources))
	for name := range schema.Resources {
		resourceNames = append(resourceNames, name)
	}
	sort.Slice(resourceNames, func(i, j int) bool {
		return len(resourceNames[i]) > len(resourceNames[j])
	})

	// First pass: set resource versions so we can compare against them.
	for path, version := range versions {
		if info, ok := schema.Resources[path]; ok {
			info.MinProviderVersion = version
		}
	}

	// Second pass: set field versions, skipping those that match the resource.
	for path, version := range versions {
		if _, isResource := schema.Resources[path]; isResource {
			continue
		}
		for _, rName := range resourceNames {
			if strings.HasPrefix(path, rName+".") {
				fieldName := path[len(rName)+1:]
				info := schema.Resources[rName]
				if finfo, ok := info.Fields[fieldName]; ok {
					if version != info.MinProviderVersion {
						finfo.MinProviderVersion = version
					}
				}
				break
			}
		}
	}
}

// GenerateVersions produces an LrVersions map from an LR definition.
// Every resource and field gets an explicit entry. Existing entries are
// preserved; new resources get currentVersion; new fields also get
// currentVersion (which should already be provider version +1 patch).
func GenerateVersions(lr *LR, currentVersion string, existing LrVersions) LrVersions {
	result := LrVersions{}

	// Process resources: preserve existing, assign currentVersion to new ones
	for _, r := range lr.Resources {
		if v, ok := existing[r.ID]; ok {
			result[r.ID] = v
		} else {
			result[r.ID] = currentVersion
		}
	}

	// Process fields: every field gets an explicit entry
	for _, r := range lr.Resources {
		if r.Body == nil {
			continue
		}
		for _, f := range r.Body.Fields {
			if f.BasicField == nil {
				continue
			}
			fieldPath := r.ID + "." + f.BasicField.ID
			if v, ok := existing[fieldPath]; ok {
				result[fieldPath] = v
			} else {
				// New field not yet tracked — assign currentVersion
				result[fieldPath] = currentVersion
			}
		}
	}

	return result
}
