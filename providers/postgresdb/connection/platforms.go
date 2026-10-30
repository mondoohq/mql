// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "postgresdb",
		Title:   "PostgreSQL Server",
		Family:  []string{"postgresdb"},
		Kind:    []string{"api"},
		Runtime: []string{"postgresdb"},
	},
	{
		Name:    "postgresdb-database",
		Title:   "PostgreSQL Database",
		Family:  []string{"postgresdb"},
		Kind:    []string{"api"},
		Runtime: []string{"postgresdb"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
