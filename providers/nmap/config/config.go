// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nmap/connection"
	"go.mondoo.com/mql/providers/nmap/provider"
)

var Config = plugin.Provider{
	Name: "nmap",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "nmap",
	ID:      "go.mondoo.com/mql/providers/nmap",
	Version: "13.0.27",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.27"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "nmap",
			Use:   "nmap",
			Short: "a Nmap network scanner",
			Long: `Use the nmap provider to query network information using the Nmap network scanner, including open ports, services, and host information.

Requirement:
  Nmap must be installed on your system. To learn how, read https://nmap.org/download.html.

Available sub-commands:
  host <TARGET>             Scan a single host by IP address or hostname
  domain <TARGET>           Scan a domain and the hosts behind it

Examples:
  cnspec shell nmap host 192.168.1.1
  cnspec shell nmap domain example.com
  cnspec shell nmap --networks 10.0.0.0/8,192.168.0.0/16
  cnspec shell nmap --networks "192.168.1.0/24" --discover hosts
  cnspec scan nmap host 192.168.1.1
  cnspec scan nmap domain example.com
  cnspec shell nmap host 192.168.1.1 --ports 22,80,443
`,
			MinArgs: 0,
			MaxArgs: 2,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryHosts,
			},
			Flags: []plugin.Flag{
				{
					Long:    "networks",
					Type:    plugin.FlagType_List,
					Default: "",
					Desc:    "Comma-separated list of networks to scan (e.g., 10.0.0.0/8,192.168.0.0/16)",
				},
				{
					Long:    "ports",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Ports to scan (e.g., 22,80,443 or 1-1024)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=network", "category=nmap"},
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
