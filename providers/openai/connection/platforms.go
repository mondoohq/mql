// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms emitted by the OpenAI provider.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "openai",
		Title:   "OpenAI",
		Family:  []string{"openai"},
		Kind:    []string{"api"},
		Runtime: []string{"openai"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry with the given name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
