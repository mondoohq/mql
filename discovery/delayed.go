// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"slices"

	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// HandleDelayedDiscovery handles the delayed discovery of an asset.
// It connects to the asset and updates its platform information.
func HandleDelayedDiscovery(ctx context.Context, asset *inventory.Asset, runtime *providers.Runtime) (*inventory.Asset, error) {
	asset.Connections[0].DelayDiscovery = false
	if err := runtime.Connect(&plugin.ConnectReq{Asset: asset}); err != nil {
		return nil, err
	}
	asset = runtime.Provider.Connection.Asset
	slices.Sort(asset.PlatformIds)
	asset.KindString = asset.GetPlatform().GetKind()

	return asset, nil
}
