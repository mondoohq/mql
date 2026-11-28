// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestValidateClaim(t *testing.T) {
	require.NoError(t, ValidateClaim(NewContainerImageClaim("sha256:abc", "nginx:1", "")))
	require.NoError(t, ValidateClaim(NewCloudResourceClaim("aws_s3_bucket", "acme-logs")))
	require.NoError(t, ValidateClaim(NewDatabaseEndpointClaim("postgresql", "db.internal", "5432", "app")))

	// Synthetic: each case breaks one rule.
	cases := map[string]*AssetClaim{
		"unknown kind":     {Kind: "s3-bucket", Claims: map[string]string{"name": "x"}},
		"unknown key":      {Kind: AssetClaimKindDatabaseEndpoint, Claims: map[string]string{AssetClaimScheme: "postgresql", AssetClaimHost: "h", "password": "x"}},
		"empty value":      NewCloudResourceClaim("aws_s3_bucket", ""),
		"missing required": {Kind: AssetClaimKindDatabaseEndpoint, Claims: map[string]string{AssetClaimScheme: "postgresql"}},
		"nil":              nil,
	}
	for name, c := range cases {
		err := ValidateClaim(c)
		assert.ErrorIs(t, err, ErrInvalidClaim, name)
	}
}

func TestNewDatabaseEndpointClaimLeavesOutEmptyParts(t *testing.T) {
	c := NewDatabaseEndpointClaim("mysql", "db", "", "")
	assert.Equal(t, map[string]string{AssetClaimScheme: "mysql", AssetClaimHost: "db"}, c.GetClaims())
	require.NoError(t, ValidateClaim(c))
}
