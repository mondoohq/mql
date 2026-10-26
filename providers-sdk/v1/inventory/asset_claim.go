// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import "maps"

// Claim kinds and keys (ADR-305, mondoohq/server). The claims map is
// string-to-string, so each kind names its keys here.
const (
	// AssetClaimKindContainerImage describes a container image.
	AssetClaimKindContainerImage = "container-image"

	// AssetClaimDigest is the image digest, e.g. "sha256:...". It may be an
	// image INDEX digest rather than a platform image digest; AssetClaimArch
	// qualifies it where a single architecture is known. The server keys on it.
	AssetClaimDigest = "digest"
	// AssetClaimRef is free-form provenance: the reference the image was
	// addressed by. Producers differ in its form (a tag, a repo@digest string,
	// a pod status image), so it is never canonical and must not be used as a
	// key; the server keys on the digest.
	AssetClaimRef = "ref"
	// AssetClaimArch is the CPU architecture of the image, e.g. "amd64". It
	// qualifies an index digest. It is left out when unknown.
	AssetClaimArch = "arch"
	// AssetClaimManifest is the raw image manifest bytes as standard, padded
	// base64. It is proof of possession and travels on the seed lane only, never
	// on a discovery claim, and is capped at 256 KiB of raw bytes; a larger
	// manifest is left out and the rest of the claim is still sent.
	AssetClaimManifest = "manifest"
	// AssetClaimVariant is reserved to tell apart architecture variants such as
	// arm/v6 and arm/v7, which AssetClaimArch alone cannot. No producer sets it
	// yet.
	AssetClaimVariant = "variant"
)

// NewContainerImageClaim builds a container-image claim. An empty arch is left
// out of the claims rather than stored as an empty value.
func NewContainerImageClaim(digest, ref, arch string) *AssetClaim {
	claims := map[string]string{
		AssetClaimDigest: digest,
		AssetClaimRef:    ref,
	}
	if arch != "" {
		claims[AssetClaimArch] = arch
	}
	return &AssetClaim{
		Kind:   AssetClaimKindContainerImage,
		Claims: claims,
	}
}

// AddClaim appends c to the asset's claims unless an identical claim (same kind
// and same claims) is already there. A nil asset or claim is ignored. The
// signature field is not part of the comparison, so two claims that differ only
// in their signature are duplicates and the first one wins.
func (a *Asset) AddClaim(c *AssetClaim) {
	if a == nil || c == nil {
		return
	}
	for _, existing := range a.Claims {
		if existing.GetKind() == c.Kind && maps.Equal(existing.GetClaims(), c.Claims) {
			return
		}
	}
	a.Claims = append(a.Claims, c)
}
