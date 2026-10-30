// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "arista-eos",
		Title:   "Arista EOS",
		Family:  []string{"arista"},
		Kind:    []string{"network-device"},
		Runtime: []string{"arista"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static platform catalog entry for the given name.
func PlatformByName(name string) (*plugin.PlatformInfo, bool) {
	p, ok := platformsByName[name]
	return p, ok
}
