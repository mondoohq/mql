// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "mysqldb",
		Title:   "MySQL Server",
		Family:  []string{"mysqldb"},
		Kind:    []string{"api"},
		Runtime: []string{"mysqldb"},
	},
	{
		Name:    "mysqldb-database",
		Title:   "MySQL Database",
		Family:  []string{"mysqldb"},
		Kind:    []string{"api"},
		Runtime: []string{"mysqldb"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
