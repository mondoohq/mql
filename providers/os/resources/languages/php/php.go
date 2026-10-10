// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package php

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Composer package URL.
// See https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/composer-definition.md
func NewPackageUrl(name string, version string) string {
	// Composer names are "vendor/package"
	namespace := ""
	pkg := name

	if ns, p, ok := strings.Cut(name, "/"); ok {
		namespace = ns
		pkg = p
	}

	return packageurl.NewPackageURL(
		packageurl.TypeComposer,
		namespace,
		pkg,
		version,
		nil,
		"").String()
}

// NewCpes creates CPE entries for a Composer package.
func NewCpes(name string, version string) []string {
	cpes := []string{}

	// Extract vendor from Composer name (vendor/package)
	vendor := name
	product := name
	if v, p, ok := strings.Cut(name, "/"); ok {
		vendor = v
		product = p
	}

	cpeEntries, err := cpe.NewPackage2Cpe(vendor, product, version, "", "")
	if err != nil {
		log.Warn().Str("name", name).Str("version", version).Err(err).Msg("failed to create cpe for PHP package")
	} else if len(cpeEntries) > 0 {
		cpes = append(cpes, cpeEntries...)
	}
	return cpes
}

// NewEvidenceList converts a list of file paths to evidence entries.
func NewEvidenceList(evidence []string) []*sbom.Evidence {
	evidenceList := make([]*sbom.Evidence, len(evidence))
	for i, e := range evidence {
		evidenceList[i] = &sbom.Evidence{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: e,
		}
	}
	return evidenceList
}

// IsPhpExtensionOrPlatform returns true for non-package requirements
// like "php", "ext-json", "lib-libxml".
func IsPhpExtensionOrPlatform(name string) bool {
	return name == "php" ||
		strings.HasPrefix(name, "ext-") ||
		strings.HasPrefix(name, "lib-") ||
		strings.HasPrefix(name, "composer-")
}
