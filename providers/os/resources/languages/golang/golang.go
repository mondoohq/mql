// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package golang

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Go module package URL for a given module path and version.
// See https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/golang-definition.md
func NewPackageUrl(modulePath string, version string) string {
	// Split module path into namespace and name.
	// e.g., "github.com/pkg/errors" -> namespace="github.com/pkg", name="errors"
	namespace := ""
	name := modulePath

	if idx := strings.LastIndex(modulePath, "/"); idx != -1 {
		namespace = modulePath[:idx]
		name = modulePath[idx+1:]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeGolang,
		namespace,
		name,
		version,
		nil,
		"").String()
}

// NewCpes creates CPE entries for a Go module.
func NewCpes(modulePath string, version string) []string {
	cpes := []string{}

	// Extract vendor and product from the module path.
	// e.g., "github.com/pkg/errors" -> vendor="pkg", product="errors"
	parts := strings.Split(modulePath, "/")
	var vendor, product string
	if len(parts) >= 3 {
		// github.com/org/repo or similar
		vendor = parts[len(parts)-2]
		product = parts[len(parts)-1]
	} else if len(parts) == 2 {
		vendor = parts[0]
		product = parts[1]
	} else {
		vendor = modulePath
		product = modulePath
	}

	// Strip major version suffix from product (e.g., "v2" from "bar/v2")
	if len(product) > 1 && product[0] == 'v' && product[1] >= '0' && product[1] <= '9' {
		if len(parts) >= 2 {
			product = parts[len(parts)-2]
			if len(parts) >= 3 {
				vendor = parts[len(parts)-3]
			}
		}
	}

	// Clean version: strip "v" prefix for CPE
	cleanVer := strings.TrimPrefix(version, "v")

	cpeEntries, err := cpe.NewPackage2Cpe(vendor, product, cleanVer, "", "")
	if err != nil {
		log.Warn().Str("module", modulePath).Str("version", version).Err(err).Msg("failed to create cpe for Go module")
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
