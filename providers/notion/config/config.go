// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/notion/connection"
	"go.mondoo.com/mql/providers/notion/provider"
)

var Config = plugin.Provider{
	Name:    "notion",
	ID:      "go.mondoo.com/mql/providers/notion",
	Version: "14.0.1",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root: "notion",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "14.0.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "notion",
			Use:   "notion",
			Short: "a Notion workspace",
			Long: fmt.Sprintf(`
Use the notion provider to query the users, bot identity, and shared pages
and databases visible to a Notion internal integration.

Authentication uses an internal integration token:

  cnspec shell notion --token <secret_...>

You can also use the default environment variable '%s' to provide your
token.
`,
				connection.NOTION_TOKEN_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Notion internal integration token",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}
