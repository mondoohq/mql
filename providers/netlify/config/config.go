// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/providers/netlify/provider"
)

var Config = plugin.Provider{
	Name: "netlify",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "netlify",
	ID:      "go.mondoo.com/mql/providers/netlify",
	Version: "13.1.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "netlify",
			Use:   "netlify",
			Short: "a Netlify account",
			Long: `Use the netlify provider to query the configuration and security posture of your Netlify accounts and sites.

The token is a Netlify personal access token, created under User settings >
Applications > Personal access tokens. The token inherits your account roles,
so a token issued by a member rather than an owner sees a narrower resource
tree.

Examples:
  cnspec shell netlify --token <access_token>
  cnspec scan netlify --token <access_token>
  cnspec scan netlify --token <access_token> --account <account_slug>

Notes:
  If you set the NETLIFY_AUTH_TOKEN environment variable, you can omit the token flag.
`,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryAccounts,
				connection.DiscoverySites,
			},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Netlify personal access token for authentication",
				},
				{
					Long:    "account",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Scope the scan to a single Netlify account (slug or ID)",
				},
			},
		},
	},
}
