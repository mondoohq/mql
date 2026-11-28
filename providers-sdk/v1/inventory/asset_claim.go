// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"errors"
	"fmt"
	"maps"
)

// Claim kinds and keys. The claims map is
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

// Claim kinds for an asset that is named but was not scanned, such as the far
// end of a relationship a dataset reports (ADR 060). The server can recognise
// the same thing later from these facts; until it does, the end stays
// unjoined.
const (
	// AssetClaimKindCloudResource describes a cloud resource as
	// infrastructure as code declares it.
	AssetClaimKindCloudResource = "cloud-resource"
	// AssetClaimType is the declaring resource type as written, e.g.
	// "aws_s3_bucket" or "AWS::S3::Bucket".
	AssetClaimType = "type"
	// AssetClaimName is the name the resource gets, e.g. the bucket name.
	AssetClaimName = "name"

	// AssetClaimKindDatabaseEndpoint describes a database by the endpoint a
	// connection URL names. The producer normalizes the URL first: no user
	// information, query or fragment reaches a claim.
	AssetClaimKindDatabaseEndpoint = "database-endpoint"
	// AssetClaimScheme is the URL scheme, e.g. "postgresql".
	AssetClaimScheme = "scheme"
	// AssetClaimHost is the first host of the URL.
	AssetClaimHost = "host"
	// AssetClaimPort is the port, in decimal. Left out when the URL has none.
	AssetClaimPort = "port"
	// AssetClaimDatabase is the database the URL names. Left out when none.
	AssetClaimDatabase = "database"
)

// assetClaimKeys lists, per claim kind, the keys a claim of that kind may
// carry and whether each is required.
var assetClaimKeys = map[string]map[string]bool{
	AssetClaimKindContainerImage: {
		AssetClaimDigest: true, AssetClaimRef: false, AssetClaimArch: false,
		AssetClaimManifest: false, AssetClaimVariant: false,
	},
	AssetClaimKindCloudResource: {AssetClaimType: true, AssetClaimName: true},
	AssetClaimKindDatabaseEndpoint: {
		AssetClaimScheme: true, AssetClaimHost: true, AssetClaimPort: false, AssetClaimDatabase: false,
	},
}

// ErrInvalidClaim is returned, wrapped, by ValidateClaim.
var ErrInvalidClaim = errors.New("invalid asset claim")

// ValidateClaim checks that c is of a known kind, carries only that kind's
// keys, has every required key, and has no empty value.
func ValidateClaim(c *AssetClaim) error {
	if c == nil {
		return fmt.Errorf("%w: nil", ErrInvalidClaim)
	}
	keys, ok := assetClaimKeys[c.GetKind()]
	if !ok {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidClaim, c.GetKind())
	}
	for k, v := range c.GetClaims() {
		if _, ok := keys[k]; !ok {
			return fmt.Errorf("%w: %s claim has unknown key %q", ErrInvalidClaim, c.GetKind(), k)
		}
		if v == "" {
			return fmt.Errorf("%w: %s claim has an empty %q", ErrInvalidClaim, c.GetKind(), k)
		}
	}
	for k, required := range keys {
		if _, ok := c.GetClaims()[k]; required && !ok {
			return fmt.Errorf("%w: %s claim has no %q", ErrInvalidClaim, c.GetKind(), k)
		}
	}
	return nil
}

// NewCloudResourceClaim builds a cloud-resource claim.
func NewCloudResourceClaim(resourceType, name string) *AssetClaim {
	return &AssetClaim{
		Kind:   AssetClaimKindCloudResource,
		Claims: map[string]string{AssetClaimType: resourceType, AssetClaimName: name},
	}
}

// NewDatabaseEndpointClaim builds a database-endpoint claim from a normalized
// connection URL's parts. An empty port or database is left out.
func NewDatabaseEndpointClaim(scheme, host, port, database string) *AssetClaim {
	claims := map[string]string{AssetClaimScheme: scheme, AssetClaimHost: host}
	if port != "" {
		claims[AssetClaimPort] = port
	}
	if database != "" {
		claims[AssetClaimDatabase] = database
	}
	return &AssetClaim{Kind: AssetClaimKindDatabaseEndpoint, Claims: claims}
}
