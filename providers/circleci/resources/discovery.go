// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Discover returns the assets reachable through this CircleCI connection.
// The MVP models a single asset per token (the connected account itself),
// so there are no child assets to enumerate. Per-organization or
// per-project child assets can be added here in a later iteration.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	return &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}, nil
}
