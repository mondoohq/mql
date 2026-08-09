// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/notion/connection"
)

// Discover returns the assets reachable through this Notion connection. The
// MVP models a single asset per integration (the connected workspace
// itself), which the provider surfaces as the root asset rather than as a
// discovered child, so this returns no child assets.
//
// TODO: when per-page or per-database child assets are added, emit them here
// and have their lister consult conn.Filters (per CLAUDE.md 3.5) so
// --filters is honored rather than silently ignored.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.NotionConnection)
	_ = conn

	return &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}, nil
}
