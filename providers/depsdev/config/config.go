// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/depsdev/connection"
	"go.mondoo.com/mql/providers/depsdev/provider"
)

var Config = plugin.Provider{
	Name: "depsdev",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "depsdev",
	ID:      "go.mondoo.com/mql/providers/depsdev",
	Version: "13.1.10",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.10"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "depsdev",
			Use:   "depsdev [path-to-go.mod]",
			Short: "deps.dev dependency analysis",
			Long: `Use the depsdev provider to query Go module dependency information from the deps.dev API.

Point it at a go.mod file to check all direct dependencies:

  mql shell depsdev ./go.mod

Or use it without arguments and query individual packages:

  mql shell depsdev
  > depsdev.package("github.com/rs/zerolog") { latestVersion latestPublished }
`,
			MinArgs:   0,
			MaxArgs:   1,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "path",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to a go.mod file",
				},
			},
		},
	},
}
