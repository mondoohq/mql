// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package terraform

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/sbom"
)

const (
	// DefaultRegistry is the registry a bare provider source address refers to.
	DefaultRegistry = "registry.terraform.io"
	// OpenTofuRegistry serves OpenTofu's own provider namespace. Its providers
	// are distinct artifacts from the HashiCorp ones even where the namespace
	// and type match, so they carry their own purl type.
	OpenTofuRegistry = "registry.opentofu.org"

	// PurlTypeProvider identifies a Terraform provider.
	PurlTypeProvider = "terraform"
	// PurlTypeOpenTofuProvider identifies an OpenTofu provider.
	PurlTypeOpenTofuProvider = "opentofu"
)

// NewPackageUrl creates a package URL for a provider served by host. An empty
// host, or the default registry, yields the plain "terraform" type.
func NewPackageUrl(host, namespace, providerType, version string) string {
	return packageurl.NewPackageURL(
		PurlTypeForHost(host),
		namespace,
		providerType,
		version,
		nil,
		"").String()
}

// PurlTypeForHost maps a registry host to the purl type its providers use.
//
// A private registry keeps the "terraform" type: it serves the Terraform
// protocol, and giving every private host its own type would mint a type per
// customer. The cost is that a private provider shares a coordinate with a
// public one of the same namespace/type — the source address is preserved on
// the package so the two remain distinguishable downstream.
func PurlTypeForHost(host string) string {
	if host == OpenTofuRegistry {
		return PurlTypeOpenTofuProvider
	}
	return PurlTypeProvider
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

// ParseProviderSource splits a provider source address into its registry host,
// namespace and type. A source may name its registry
// ("registry.terraform.io/hashicorp/aws", "artifactory.acme.com/tf/docker") or
// omit it ("hashicorp/aws"), in which case host is empty and the default
// registry is implied.
//
// The host is recognised by the first segment containing a dot, which is what
// Terraform itself requires of a registry hostname. Counting segments instead
// is wrong: it reads the namespace of a four-segment private address as a host
// and hands back a type containing slashes.
func ParseProviderSource(source string) (host, namespace, providerType string) {
	parts := strings.Split(source, "/")
	if len(parts) > 1 && strings.Contains(parts[0], ".") {
		host = parts[0]
		parts = parts[1:]
	}

	switch len(parts) {
	case 0:
		return host, "", ""
	case 1:
		return host, "", parts[0]
	default:
		// Everything but the last segment is the namespace. A provider address
		// is <NAMESPACE>/<TYPE>, so this is normally one segment; joining
		// rather than indexing keeps a longer private address intact instead
		// of silently dropping a level.
		return host, strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1]
	}
}
