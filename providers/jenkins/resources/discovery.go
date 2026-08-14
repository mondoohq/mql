// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// Discover returns the assets reachable through this Jenkins connection. The
// MVP models a single asset per controller (the connected controller
// itself), so there are no child assets to enumerate.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	return &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}, nil
}
