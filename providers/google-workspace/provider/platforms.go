// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "google-workspace",
		Title:   "Google Workspace",
		Family:  []string{"google"},
		Kind:    []string{"api"},
		Runtime: []string{"google-workspace"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static platform catalog entry for the given name.
func PlatformByName(name string) (*plugin.PlatformInfo, bool) {
	p, ok := platformsByName[name]
	return p, ok
}
