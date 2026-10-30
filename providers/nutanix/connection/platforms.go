// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "nutanix-prism-central",
		Title:   "Nutanix Prism Central",
		Family:  []string{Family},
		Kind:    []string{"api"},
		Runtime: []string{"nutanix"},
	},
	{
		Name:    "nutanix-cluster",
		Title:   "Nutanix Cluster",
		Family:  []string{Family},
		Kind:    []string{"api"},
		Runtime: []string{"nutanix"},
	},
	{
		Name:    "nutanix-node",
		Title:   "Nutanix Node",
		Family:  []string{Family},
		Kind:    []string{inventory.AssetKindBaremetal},
		Runtime: []string{"nutanix"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
