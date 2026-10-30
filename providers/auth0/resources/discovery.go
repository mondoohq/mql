// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
)

// Discover returns the assets reachable through this Auth0 connection. The MVP
// models a single asset per tenant (the connected tenant itself), so there are
// no child assets to enumerate. Per-application or per-connection child assets
// can be added here in a later iteration.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.Auth0Connection)
	_ = conn

	return &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}, nil
}
