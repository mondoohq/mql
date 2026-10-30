// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package julia

import (
	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Julia package URL.
// Format: pkg:julia/name@version
func NewPackageUrl(name string, version string) string {
	return packageurl.NewPackageURL(
		"julia",
		"",
		name,
		version,
		nil,
		"").String()
}

// NewEvidence creates a file evidence entry.
func NewEvidence(path string) *sbom.Evidence {
	return &sbom.Evidence{
		Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
		Value: path,
	}
}
