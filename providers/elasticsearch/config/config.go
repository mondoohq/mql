// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/elasticsearch/connection"
	"go.mondoo.com/mql/providers/elasticsearch/provider"
)

var Config = plugin.Provider{
	Name: "elasticsearch",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "elasticsearch",
	ID:      "go.mondoo.com/mql/providers/elasticsearch",
	Version: "13.0.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.3"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "elasticsearch",
			Use:   "elasticsearch [host]",
			Short: "an Elasticsearch cluster",
			Long: `Use the elasticsearch provider to query an Elasticsearch cluster.

The provider connects to the cluster's REST API and runs read-only requests to
inventory the cluster version and health, its security posture, and its users,
roles, role mappings, and API keys, so you can audit the cluster's security
posture.

Examples:
  cnspec shell elasticsearch localhost --user elastic --ask-pass
  cnspec scan elasticsearch es.contoso.com --api-key API_KEY
`,
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Elasticsearch hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "9200",
					Desc:    "Elasticsearch REST API port",
				},
				{
					Long:    "scheme",
					Type:    plugin.FlagType_String,
					Default: "https",
					Desc:    "Connection scheme: http or https",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User name for basic authentication",
				},
				{
					Long:        "password",
					Short:       "p",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Set the connection password",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:        "ask-pass",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for the connection password",
					ConfigEntry: "-",
				},
				{
					Long:        "api-key",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "API key to authenticate with (base64 of id:api_key)",
					Option:      plugin.FlagOption_Password,
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
