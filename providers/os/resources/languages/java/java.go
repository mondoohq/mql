// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a Maven package URL for a given groupId, artifactId, and version.
// See https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/maven-definition.md
func NewPackageUrl(groupId, artifactId, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeMaven,
		groupId,
		artifactId,
		version,
		nil,
		"").String()
}

// NewCpes creates CPE entries for a Maven package.
func NewCpes(groupId, artifactId, version string) []string {
	cpes := []string{}

	// Derive vendor from groupId: use last meaningful segment.
	// e.g., "org.apache.commons" -> "apache"
	// e.g., "com.google.guava" -> "google"
	vendor := vendorFromGroupId(groupId)

	cpeEntries, err := cpe.NewPackage2Cpe(vendor, artifactId, version, "", "")
	if err != nil {
		log.Warn().Str("groupId", groupId).Str("artifactId", artifactId).Str("version", version).Err(err).Msg("failed to create cpe for Java package")
	} else if len(cpeEntries) > 0 {
		cpes = append(cpes, cpeEntries...)
	}
	return cpes
}

// vendorFromGroupId extracts a vendor name from a Maven groupId.
// It skips common TLD prefixes (org, com, net, io) and returns the
// next segment as the vendor.
func vendorFromGroupId(groupId string) string {
	parts := strings.Split(groupId, ".")
	if len(parts) == 0 {
		return groupId
	}

	// Skip common TLD/domain prefixes
	skipPrefixes := map[string]bool{
		"org": true, "com": true, "net": true, "io": true,
		"de": true, "fr": true, "uk": true, "co": true,
	}

	for _, part := range parts {
		if !skipPrefixes[part] {
			return part
		}
	}

	// If all parts were skipped (unlikely), use the full groupId
	return groupId
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

// ConcreteVersion accepts a version that names one release, and rejects one that
// names a set.
//
// Gradle lets a coordinate carry a dynamic version or a range -- "1.+",
// "[1.0, 2.0[", "latest.release" -- and Maven allows the same range syntax.
// None of them says which release is present, so recording one as the version
// produces a purl that matches no release while reading downstream as a
// definite claim about what is installed. The artifact is still worth
// inventorying; its version is simply not known from the manifest, which is the
// same state as a version a BOM was meant to supply and did not.
//
// Shared because every Java manifest reader faces the same strings, and two
// copies of this rule would drift into disagreeing about the same coordinate.
func ConcreteVersion(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "[],()") || strings.HasSuffix(s, "+") || strings.Contains(s, "latest") {
		return ""
	}
	return s
}
