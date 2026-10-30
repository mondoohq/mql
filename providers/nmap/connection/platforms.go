// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms emitted by the nmap provider.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "nmap-host",
		Title:   "Nmap Host",
		Family:  []string{"nmap"},
		Kind:    []string{"api"},
		Runtime: []string{"nmap"},
	},
	{
		Name:    "nmap-domain",
		Title:   "Nmap Domain",
		Family:  []string{"nmap"},
		Kind:    []string{"api"},
		Runtime: []string{"nmap"},
	},
	{
		Name:    "nmap-org",
		Title:   "Nmap",
		Family:  []string{"nmap"},
		Kind:    []string{"api"},
		Runtime: []string{"nmap"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static platform catalog entry for the given name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
