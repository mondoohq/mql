// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nutanix/connection"
	"go.mondoo.com/mql/providers/nutanix/provider"
)

var Config = plugin.Provider{
	Name: "nutanix",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "nutanix",
	ID:      "go.mondoo.com/mql/providers/nutanix",
	Version: "13.4.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.4.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "nutanix",
			Use:   "nutanix --endpoint ENDPOINT [flags]",
			Short: "a Nutanix Prism Central instance",
			Long: `Use the nutanix provider to query Nutanix clusters, hosts, and virtual
machines through a Prism Central instance.

Authenticate with either basic auth (username and password) or an IAM API key.

Examples:
  cnspec scan nutanix --endpoint pc.example.com --user admin --ask-pass
  cnspec scan nutanix --endpoint pc.example.com --user admin --password PASSWORD --insecure
  cnspec scan nutanix --endpoint pc.example.com --api-key API_KEY
`,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryClusters,
				connection.DiscoveryNodes,
			},
			Flags: []plugin.Flag{
				{
					Long:   "endpoint",
					Type:   plugin.FlagType_String,
					Desc:   "Prism Central host: IP address or FQDN",
					Option: plugin.FlagOption_Required,
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "9440",
					Desc:    "Prism Central API port",
				},
				{
					Long: "user",
					Type: plugin.FlagType_String,
					Desc: "Username for basic authentication",
				},
				{
					Long:        "ask-pass",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for the connection password",
					ConfigEntry: "-",
				},
				{
					Long:        "password",
					Short:       "p",
					Type:        plugin.FlagType_String,
					Option:      plugin.FlagOption_Password,
					Desc:        "Password for basic authentication",
					ConfigEntry: "-",
				},
				{
					Long:        "api-key",
					Type:        plugin.FlagType_String,
					Option:      plugin.FlagOption_Password,
					Desc:        "IAM API key for service-account authentication",
					ConfigEntry: "-",
				},
				{
					Long:        "insecure",
					Short:       "k",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Skip TLS certificate verification",
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=virtualization", "provider=nutanix"},
			Key:          "kind",
			Title:        "Nutanix Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"prism-central": {
					Key:   "endpoint",
					Title: "Prism Central Endpoint",
				},
			},
		},
	},
}
