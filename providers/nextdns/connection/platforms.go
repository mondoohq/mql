// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "nextdns-account",
		Title:   "NextDNS Account",
		Family:  []string{"nextdns"},
		Kind:    []string{"api"},
		Runtime: []string{"nextdns"},
	},
	{
		Name:    "nextdns-profile",
		Title:   "NextDNS Profile",
		Family:  []string{"nextdns"},
		Kind:    []string{"api"},
		Runtime: []string{"nextdns"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
