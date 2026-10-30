// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit. It is
// derived from the vendor registry so a new supported vendor only needs a
// single entry in vendors (plus the generic fallback).
var Platforms = platformCatalog()

func platformCatalog() []*plugin.PlatformInfo {
	all := append(append([]Vendor{}, vendors...), genericVendor)
	out := make([]*plugin.PlatformInfo, len(all))
	for i, v := range all {
		out[i] = &plugin.PlatformInfo{
			Name:    v.Platform,
			Title:   v.Name,
			Family:  []string{"redfish", "bmc"},
			Kind:    []string{"api"},
			Runtime: []string{"redfish"},
		}
	}
	return out
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
