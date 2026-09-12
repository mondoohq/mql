// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mysqldb/connection"
	"go.mondoo.com/mql/providers/mysqldb/provider"
)

var Config = plugin.Provider{
	Name: "mysqldb",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "mysqldb",
	ID:      "go.mondoo.com/mql/providers/mysqldb",
	Version: "13.1.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "mysqldb",
			Use:   "mysqldb [host]",
			Short: "a MySQL or MariaDB server",
			Long: `Use the mysqldb provider to query a MySQL, MariaDB, or Percona server.

The provider connects to the server and runs read-only queries against
information_schema, performance_schema, and the system catalogs to inventory
users, roles, privileges, schemas, routines, plugins, components, and
configuration variables.

By default the provider discovers every schema on the server as its own asset.

Examples:
  cnspec shell mysqldb db.contoso.com --user root --ask-pass
  cnspec scan mysqldb db.contoso.com --tls-mode true --tls-ca ca.pem
`,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryInstance,
				connection.DiscoveryDatabases,
				connection.DiscoveryNone,
			},
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "MySQL/MariaDB hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "3306",
					Desc:    "MySQL/MariaDB TCP port",
				},
				{
					Long:    "database",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Default schema to connect to (optional)",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User name to authenticate as",
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
					Long:    "tls-mode",
					Type:    plugin.FlagType_String,
					Default: "preferred",
					Desc:    "TLS mode: false, skip-verify, preferred, or true",
				},
				{
					Long:    "tls-ca",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the trusted CA certificate for TLS verification",
				},
				{
					Long:    "tls-cert",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the client certificate for TLS client authentication",
				},
				{
					Long:    "tls-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the client private key for TLS client authentication",
				},
			},
		},
	},
}
