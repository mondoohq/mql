// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestKeepContextConfig(t *testing.T) {
	cfg := &inventory.ContextConfig{AssetPath: "infra"}

	// a provider that answered with a new asset
	res := &plugin.ConnectRes{Asset: &inventory.Asset{Name: "new"}}
	keepContextConfig(&inventory.Asset{ContextConfig: cfg}, res)
	assert.Equal(t, "infra", res.Asset.ContextConfig.GetAssetPath())

	// a config the provider set itself wins
	own := &inventory.ContextConfig{AssetPath: "."}
	res = &plugin.ConnectRes{Asset: &inventory.Asset{ContextConfig: own}}
	keepContextConfig(&inventory.Asset{ContextConfig: cfg}, res)
	assert.Same(t, own, res.Asset.ContextConfig)

	// nothing to keep, or nowhere to put it
	keepContextConfig(&inventory.Asset{}, res)
	keepContextConfig(&inventory.Asset{ContextConfig: cfg}, nil)
	keepContextConfig(&inventory.Asset{ContextConfig: cfg}, &plugin.ConnectRes{})
}
