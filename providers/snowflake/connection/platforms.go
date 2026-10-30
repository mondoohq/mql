// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:   "snowflake",
		Title:  "Snowflake Account",
		Family: []string{"snowflake"},
		Kind:   []string{"api"},
	},
	{
		Name:   "snowflake-database",
		Title:  "Snowflake Database",
		Family: []string{"snowflake"},
		Kind:   []string{"api"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
