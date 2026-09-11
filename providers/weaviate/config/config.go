// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/weaviate/connection"
	"go.mondoo.com/mql/providers/weaviate/provider"
)

var Config = plugin.Provider{
	Name: "weaviate",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "weaviate.instance",
	ID:      "go.mondoo.com/mql/providers/weaviate",
	Version: "13.0.4",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.4"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "weaviate",
			Use:   "weaviate [host]",
			Short: "a Weaviate vector database",
			Long: `Use the weaviate provider to query a Weaviate vector database server.

The provider connects to the server's REST API and runs read-only requests to
inventory the server's version and modules, collections, role-based access
control roles and permissions, users, and cluster nodes, so you can audit the
server's security posture.

By default the provider discovers every collection on the server as its own
asset.

Examples:
  cnspec shell weaviate localhost --api-key API_KEY
  cnspec scan weaviate my-instance.example.com --scheme https --api-key API_KEY
`,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryInstance,
				connection.DiscoveryCollections,
				connection.DiscoveryNone,
			},
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Weaviate hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "8080",
					Desc:    "Weaviate REST API port",
				},
				{
					Long:    "scheme",
					Type:    plugin.FlagType_String,
					Default: "http",
					Desc:    "Connection scheme: http or https",
				},
				{
					Long:        "api-key",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "API key to authenticate with",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:        "ask-api-key",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for the API key",
					ConfigEntry: "-",
				},
				{
					Long:    "tls-ca",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the trusted CA certificate for TLS verification",
				},
				{
					Long:    "tls-insecure",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Skip TLS certificate verification (testing only)",
				},
			},
		},
	},
}
