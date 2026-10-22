// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestKeepAssetClaims(t *testing.T) {
	claim := inventory.NewContainerImageClaim("sha256:abc", "alpine:3.20", "amd64")

	// a provider that answered with a new asset
	res := &plugin.ConnectRes{Asset: &inventory.Asset{Name: "new"}}
	keepAssetClaims(&inventory.Asset{Claims: []*inventory.AssetClaim{claim}}, res)
	if assert.Len(t, res.Asset.Claims, 1) {
		assert.Equal(t, claim.Claims, res.Asset.Claims[0].Claims)
		assert.NotSame(t, claim, res.Asset.Claims[0])
	}

	// claims the provider set itself win
	own := inventory.NewContainerImageClaim("sha256:def", "alpine:3.19", "")
	res = &plugin.ConnectRes{Asset: &inventory.Asset{Claims: []*inventory.AssetClaim{own}}}
	keepAssetClaims(&inventory.Asset{Claims: []*inventory.AssetClaim{claim}}, res)
	if assert.Len(t, res.Asset.Claims, 1) {
		assert.Same(t, own, res.Asset.Claims[0])
	}

	// nothing to keep, or nowhere to put it
	keepAssetClaims(&inventory.Asset{}, res)
	keepAssetClaims(nil, res)
	keepAssetClaims(&inventory.Asset{Claims: []*inventory.AssetClaim{claim}}, nil)
	keepAssetClaims(&inventory.Asset{Claims: []*inventory.AssetClaim{claim}}, &plugin.ConnectRes{})
}
