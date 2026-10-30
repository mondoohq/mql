// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewContainerImageClaim(t *testing.T) {
	t.Run("with arch", func(t *testing.T) {
		c := NewContainerImageClaim("sha256:abc", "docker.io/library/alpine:3.20", "arm64")
		assert.Equal(t, AssetClaimKindContainerImage, c.Kind)
		assert.Equal(t, map[string]string{
			AssetClaimDigest: "sha256:abc",
			AssetClaimRef:    "docker.io/library/alpine:3.20",
			AssetClaimArch:   "arm64",
		}, c.Claims)
		assert.Empty(t, c.Signature)
	})

	t.Run("empty arch is omitted", func(t *testing.T) {
		c := NewContainerImageClaim("sha256:abc", "docker.io/library/alpine:3.20", "")
		assert.Equal(t, map[string]string{
			AssetClaimDigest: "sha256:abc",
			AssetClaimRef:    "docker.io/library/alpine:3.20",
		}, c.Claims)
		assert.NotContains(t, c.Claims, AssetClaimArch)
	})
}

func TestAddClaimDedupes(t *testing.T) {
	a := &Asset{}
	a.AddClaim(NewContainerImageClaim("sha256:abc", "alpine:3.20", "amd64"))
	a.AddClaim(NewContainerImageClaim("sha256:abc", "alpine:3.20", "amd64"))
	assert.Len(t, a.Claims, 1)

	a.AddClaim(NewContainerImageClaim("sha256:abc", "alpine:3.20", "arm64"))
	assert.Len(t, a.Claims, 2)
}

func TestAddClaimNilSafe(t *testing.T) {
	var nilAsset *Asset
	assert.NotPanics(t, func() {
		nilAsset.AddClaim(NewContainerImageClaim("sha256:abc", "alpine:3.20", ""))
	})

	a := &Asset{}
	assert.NotPanics(t, func() { a.AddClaim(nil) })
	assert.Empty(t, a.Claims)

	// a nil element already in the slice must not panic the dedupe
	withNil := &Asset{Claims: []*AssetClaim{nil}}
	assert.NotPanics(t, func() {
		withNil.AddClaim(NewContainerImageClaim("sha256:abc", "alpine:3.20", ""))
	})
	assert.Len(t, withNil.Claims, 2)
}
