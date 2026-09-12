// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/providers/digitalocean/provider"
)

var Config = plugin.Provider{
	Name: "digitalocean",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "digitalocean",
	ID:      "go.mondoo.com/mql/providers/digitalocean",
	Version: "13.15.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.15.3"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "digitalocean",
			Use:   "digitalocean",
			Short: "a DigitalOcean account",
			Long: `Use the digitalocean provider to query resources in a DigitalOcean account.

Examples:
  cnspec shell digitalocean --token <api-token>
  cnspec shell digitalocean
  cnspec scan digitalocean --discover all --filters tags=production

Notes:
  If you set the DIGITALOCEAN_TOKEN environment variable, you can omit the token flag.
`,
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryDatabases,
				connection.DiscoveryKubernetes,
				connection.DiscoveryLoadBalancers,
				connection.DiscoveryFirewalls,
				connection.DiscoverySpacesBuckets,
				connection.DiscoveryGradientaiAgents,
			},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "DigitalOcean personal access token (env: DIGITALOCEAN_TOKEN)",
				},
				{
					Long:    "filters",
					Type:    plugin.FlagType_KeyValue,
					Default: "",
					Desc:    "Filter discovered assets, e.g., --filters regions=nyc1,sfo3 --filters exclude:regions=ams3 --filters tags=production,web --filters exclude:tags=temporary",
				},
			},
		},
	},
}
