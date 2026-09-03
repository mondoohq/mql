// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpp

import (
	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/v13/sbom"
)

// NewPackageUrl creates a Conan package URL for a given package name and version.
// See https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#conan
func NewPackageUrl(name string, version string) string {
	return NewConanPackageUrl(ConanCoordinate{Name: name, Version: version})
}

// ConanCoordinate is everything a Conan reference states about a package's
// identity. A reference is `name/version[@user/channel][#revision]`, and the
// parts after the version are not decoration: a recipe from a user and channel
// is a different package from the ConanCenter one of the same name, built from
// a different recipe by a different party.
type ConanCoordinate struct {
	Name    string
	Version string
	User    string
	Channel string
	// Revision is parsed so a reference carrying one resolves correctly, but it
	// deliberately does NOT reach the purl — see NewConanPackageUrl.
	Revision string
}

// NewConanPackageUrl creates a Conan package URL carrying the package's
// identity. Per the purl spec's conan type the user is the NAMESPACE and the
// channel is a qualifier; a reference with no user has an empty namespace,
// which is the ConanCenter form.
//
// The spec also requires the namespace when a channel is present, since a
// channel alone does not identify the recipe's origin. A malformed reference
// carrying a channel and no user therefore drops the channel rather than
// emitting a purl that cannot round-trip.
//
// The recipe revision is deliberately omitted, though the spec permits an
// `rrev` qualifier. The purl is the correlation key an advisory is matched on,
// and no advisory will ever state a recipe revision — it identifies the exact
// recipe content that produced a build, which is below the granularity anyone
// publishes vulnerabilities at. Including it can only turn a match into a miss.
// User and channel are the opposite case: they change WHICH package this is, so
// omitting them makes a private package inherit the public one's advisories.
func NewConanPackageUrl(c ConanCoordinate) string {
	qualifiers := map[string]string{}
	if c.User != "" && c.Channel != "" {
		qualifiers["channel"] = c.Channel
	}
	var q packageurl.Qualifiers
	if len(qualifiers) > 0 {
		q = packageurl.QualifiersFromMap(qualifiers)
	}
	return packageurl.NewPackageURL(
		packageurl.TypeConan,
		c.User,
		c.Name,
		// ResolvedVersion, not Version: a range must not reach the purl either.
		// Building the purl from the raw version let "fmt/[>=9.0]" through as
		// pkg:conan/fmt@%5B%3E%3D9.0%5D while the package's own Version field
		// was correctly empty — one coordinate disagreeing with itself.
		c.ResolvedVersion(),
		q,
		"").String()
}

// NewVcpkgPackageUrl creates a vcpkg package URL for a given package name and
// version. vcpkg has no registered purl type in the spec; the de-facto
// convention (as used by common SBOM tooling) is the literal type "vcpkg".
func NewVcpkgPackageUrl(name string, version string) string {
	return NewVcpkgPackageUrlWithQualifiers(name, version, nil)
}

// NewVcpkgPackageUrlWithQualifiers creates a vcpkg package URL carrying extra
// qualifiers, for the facts a manifest states about a dependency that are not
// its resolved version — a `version>=` floor, or the triplet an install tree
// resolved it for.
//
// A floor is deliberately a qualifier and never the version. vcpkg resolves a
// dependency through the registry baseline, routinely to a version ABOVE the
// floor, so promoting it would produce a coordinate the project does not use
// and match advisories against code it does not run.
func NewVcpkgPackageUrlWithQualifiers(name, version string, qualifiers map[string]string) string {
	var q packageurl.Qualifiers
	if len(qualifiers) > 0 {
		q = packageurl.QualifiersFromMap(qualifiers)
	}
	return packageurl.NewPackageURL(
		"vcpkg",
		"",
		name,
		version,
		q,
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
