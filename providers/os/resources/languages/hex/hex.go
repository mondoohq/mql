// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package hex provides shared helpers for Elixir and Erlang Hex packages.
package hex

import (
	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Hex package URL (shared by Elixir and Erlang).
// See https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/hex-definition.md
func NewPackageUrl(name string, version string) string {
	return packageurl.NewPackageURL(
		"hex",
		"",
		name,
		version,
		nil,
		"").String()
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
