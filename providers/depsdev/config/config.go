// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/depsdev/provider"
)

var Config = plugin.Provider{
	Name:            "depsdev",
	ID:              "go.mondoo.com/mql/v13/providers/depsdev",
	Version:         "13.0.1",
	ConnectionTypes: []string{provider.DefaultConnectionType},
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
