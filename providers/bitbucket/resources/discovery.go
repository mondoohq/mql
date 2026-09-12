// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitbucket/connection"
)

// Discover returns the assets reachable through this Bitbucket connection.
// The MVP models a single asset per connection (the connected workspace
// itself), so there are no child assets to enumerate and no discovery
// targets to filter. When per-repository child assets are added here in a
// later iteration, their lister must consult conn.Filters (per CLAUDE.md
// §3.5) so that --filters is honored rather than silently ignored.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.BitbucketConnection)
	_ = conn

	return &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}, nil
}
