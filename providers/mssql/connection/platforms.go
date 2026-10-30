// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit. The
// build exports it into dist/mssql.json so the CLI and generated docs can list
// what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "mssql",
		Title:   "Microsoft SQL Server",
		Family:  []string{"mssql"},
		Kind:    []string{"api"},
		Runtime: []string{"mssql"},
	},
	{
		Name:    "mssql-database",
		Title:   "Microsoft SQL Server Database",
		Family:  []string{"mssql"},
		Kind:    []string{"api"},
		Runtime: []string{"mssql"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
