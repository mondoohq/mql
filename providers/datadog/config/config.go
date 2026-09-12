// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/datadog/connection"
	"go.mondoo.com/mql/providers/datadog/provider"
)

var Config = plugin.Provider{
	Name: "datadog",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "datadog",
	ID:      "go.mondoo.com/mql/providers/datadog",
	Version: "13.0.23",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.23"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "datadog",
			Use:   "datadog",
			Short: "a Datadog account",
			Long: `Use the datadog provider to query resources in a Datadog account.

Examples:
  mql shell datadog --api-key <key> --app-key <key>
  mql shell datadog

Notes:
  Set DD_API_KEY and DD_APP_KEY environment variables to avoid passing keys on the command line.
  Set DD_SITE for non-US regions (e.g., datadoghq.eu).
`,
			MinArgs:   0,
			MaxArgs:   0,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Datadog API key (env: DD_API_KEY)",
				},
				{
					Long:    "app-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Datadog application key (env: DD_APP_KEY)",
				},
				{
					Long:    "site",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Datadog site (env: DD_SITE, e.g., datadoghq.eu, us3.datadoghq.com)",
				},
			},
		},
	},
}
