// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms emitted by the shodan provider.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "shodan-host",
		Title:   "Shodan Host",
		Family:  []string{"shodan"},
		Kind:    []string{"api"},
		Runtime: []string{"shodan"},
	},
	{
		Name:    "shodan-domain",
		Title:   "Shodan Domain",
		Family:  []string{"shodan"},
		Kind:    []string{"api"},
		Runtime: []string{"shodan"},
	},
	{
		Name:    "shodan-org",
		Title:   "Shodan Organization",
		Family:  []string{"shodan"},
		Kind:    []string{"api"},
		Runtime: []string{"shodan"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static platform catalog entry for the given name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
