// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Discover is intentionally a no-op for the Grafana provider. The provider
// operates in single-org scope — there are no sub-assets to discover.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	return nil, nil
}
