// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package haskell

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Hackage package URL.
func NewPackageUrl(name string, version string) string {
	return packageurl.NewPackageURL(
		"hackage",
		"",
		name,
		version,
		nil,
		"").String()
}

// NewCpes creates CPE entries for a Haskell package.
func NewCpes(name string, version string) []string {
	cpes := []string{}
	cpeEntries, err := cpe.NewPackage2Cpe(name, name, version, "", "")
	if err != nil {
		log.Warn().Str("name", name).Str("version", version).Err(err).Msg("failed to create cpe for Haskell package")
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

// ParseHackageRef parses a Stack hackage reference like "name-version@sha256:hash"
// into name and version. The version is the last hyphen-separated numeric segment.
func ParseHackageRef(ref string) (name, version string) {
	// Strip @sha256:... suffix
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}

	// Split "name-version" where version is the trailing numeric part.
	// e.g., "aeson-2.2.1.0" -> "aeson", "2.2.1.0"
	// e.g., "bytestring-0.12.1.0" -> "bytestring", "0.12.1.0"
	// Find the last hyphen before a digit
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == '-' {
			// Check if what follows starts with a digit
			if i+1 < len(ref) && ref[i+1] >= '0' && ref[i+1] <= '9' {
				return ref[:i], ref[i+1:]
			}
		}
	}

	return ref, ""
}
