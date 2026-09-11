// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/shodan/connection"
	"go.mondoo.com/mql/providers/shodan/provider"
)

var Config = plugin.Provider{
	Name: "shodan",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "shodan",
	ID:      "go.mondoo.com/mql/providers/shodan",
	Version: "13.2.13",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.2.13"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "shodan",
			Use:   "shodan",
			Short: "a Shodan account",
			Long: `Use the shodan provider to query domain and IP security information in the Shodan search engine.

Available sub-commands:
  host <TARGET>             Query a single host by IP address or hostname
  domain <TARGET>           Query a domain and the hosts Shodan associates with it

Examples:
  cnspec shell shodan --token <api-token>
  cnspec shell shodan host example.com
  cnspec shell shodan domain example.com
  cnspec shell shodan --networks <ip-range> --discover hosts
  cnspec scan shodan --token <api-token>
  cnspec scan shodan host 192.168.1.1
  cnspec scan shodan domain example.com

Notes:
  If you set the SHODAN_TOKEN environment variable, you can omit the token flag.
`,
			MinArgs: 0,
			MaxArgs: 2,
			Discovery: []string{
				connection.DiscoveryHosts,
			},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Shodan API token",
				},
				{
					Long:    "networks",
					Type:    plugin.FlagType_List,
					Default: "",
					Desc:    "Comma-separated list of IP ranges to query (e.g., 10.0.0.0/8,192.168.0.0/16)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=network", "category=shodan"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"host":   nil,
				"domain": nil,
				"org":    nil,
			},
		},
	},
}
