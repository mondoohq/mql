// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import "maps"

// Claim kinds and keys (ADR-285, mondoohq/server). The claims map is
// string-to-string, so each kind names its keys here.
const (
	// AssetClaimKindContainerImage describes a container image.
	AssetClaimKindContainerImage = "container-image"

	// AssetClaimDigest is the image digest, e.g. "sha256:...".
	AssetClaimDigest = "digest"
	// AssetClaimRef is the reference the image was addressed by.
	AssetClaimRef = "ref"
	// AssetClaimArch is the CPU architecture of the image.
	AssetClaimArch = "arch"
	// AssetClaimManifest is the image manifest.
	AssetClaimManifest = "manifest"
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
// and same claims) is already there. A nil asset or claim is ignored.
func (a *Asset) AddClaim(c *AssetClaim) {
	if a == nil || c == nil {
		return
	}
	for _, existing := range a.Claims {
		if existing.GetKind() == c.Kind && maps.Equal(existing.Claims, c.Claims) {
			return
		}
	}
	a.Claims = append(a.Claims, c)
}
