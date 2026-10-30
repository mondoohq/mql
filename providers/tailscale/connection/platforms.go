// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "tailscale-org",
		Title:   "Tailscale Organization",
		Family:  []string{"tailscale"},
		Kind:    []string{"api"},
		Runtime: []string{"tailscale"},
	},
	{
		Name:    "tailscale-device",
		Title:   "Tailscale Device",
		Family:  []string{"tailscale"},
		Kind:    []string{"api"},
		Runtime: []string{"tailscale"},
	},
	{
		Name:    "tailscale-user",
		Title:   "Tailscale User",
		Family:  []string{"tailscale"},
		Kind:    []string{"api"},
		Runtime: []string{"tailscale"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
