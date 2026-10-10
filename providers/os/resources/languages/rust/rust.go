// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package rust

import (
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Cargo package URL for a given crate name and version.
// See https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/cargo-definition.md
func NewPackageUrl(name string, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeCargo,
		"",
		name,
		version,
		nil,
		"").String()
}

// NewCpes creates CPE entries for a Cargo crate.
// Rust crates are uniquely named on crates.io, so vendor = product = crate name.
func NewCpes(name string, version string) []string {
	cpes := []string{}
	cpeEntries, err := cpe.NewPackage2Cpe(name, name, version, "", "")
	if err != nil {
		log.Warn().Str("name", name).Str("version", version).Err(err).Msg("failed to create cpe for Rust crate")
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
