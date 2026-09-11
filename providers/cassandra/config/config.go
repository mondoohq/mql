// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cassandra/connection"
	"go.mondoo.com/mql/providers/cassandra/provider"
)

var Config = plugin.Provider{
	Name: "cassandra",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "cassandra",
	ID:      "go.mondoo.com/mql/providers/cassandra",
	Version: "13.0.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.3"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "cassandra",
			Use:   "cassandra [host]",
			Short: "an Apache Cassandra cluster",
			Long: `Use the cassandra provider to query an Apache Cassandra cluster.

The provider connects over CQL and runs read-only queries against the system
and system_auth keyspaces and the system_views.settings virtual table to
inventory the cluster version, its security posture, and its roles, nodes, and
keyspaces, so you can audit the cluster's security posture.

Examples:
  cnspec shell cassandra localhost --user cassandra --ask-pass
  cnspec scan cassandra db.contoso.com --user auditor --ask-pass --tls
`,
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Cassandra hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "9042",
					Desc:    "Cassandra CQL native transport port",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Role name to authenticate as",
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
					Long:    "tls",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Connect over TLS",
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
