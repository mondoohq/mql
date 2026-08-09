// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
)

// Discover returns the assets reachable through this Bitbucket connection.
// The MVP models a single asset per connection (the connected workspace
// itself), so there are no child assets to enumerate. Per-repository child
// assets can be added here in a later iteration.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.BitbucketConnection)
	_ = conn

	return &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}, nil
}
