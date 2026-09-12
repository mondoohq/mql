// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mssql/connection"
	"go.mondoo.com/mql/providers/mssql/provider"
)

var Config = plugin.Provider{
	Name: "mssql",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "mssql",
	ID:      "go.mondoo.com/mql/providers/mssql",
	Version: "13.1.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "mssql",
			Use:   "mssql [host]",
			Short: "a Microsoft SQL Server instance",
			Long: `Use the mssql provider to query a Microsoft SQL Server instance.

The provider connects to a SQL Server instance over TDS and runs read-only
catalog queries (sys.* and msdb.*) to inventory server principals, databases,
permissions, credentials, linked servers, audit settings, and encryption keys.

Authentication supports SQL logins, Windows (NTLM) integrated auth, and
Microsoft Entra ID (Azure AD) access tokens. By default the provider discovers
every online database on the instance as its own asset.

Examples:
  cnspec shell mssql sql.contoso.com --user sa --ask-pass
  cnspec scan mssql sql.contoso.com --instance SQL2022 --auth windows --user 'CONTOSO\audit' --ask-pass
  cnspec scan mssql sql.contoso.com --auth azure --user audit@contoso.com --token <access-token>
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
					Desc:    "SQL Server hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "1433",
					Desc:    "SQL Server TCP port",
				},
				{
					Long:    "instance",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Named instance (resolved via SQL Browser when the port is unknown)",
				},
				{
					Long:    "database",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Scope the connection to a single database",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Login name (SQL login, DOMAIN\\user, or user principal name)",
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
					Long:        "token",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Access token for Microsoft Entra ID (Azure AD) authentication",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:    "auth",
					Type:    plugin.FlagType_String,
					Default: "sql",
					Desc:    "Authentication mode: sql, windows, kerberos, or azure",
					// Not persisted to the CLI config: cnquery's own config
					// reserves the top-level `auth` key for an authentication
					// map, and binding a string flag onto it makes every
					// mssql invocation fail to load the config.
					ConfigEntry: "-",
				},
				{
					Long:    "encrypt",
					Type:    plugin.FlagType_String,
					Default: "mandatory",
					Desc:    "TDS encryption mode: strict, mandatory, optional, or disable",
				},
				{
					Long:    "trust-server-certificate",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Skip TLS certificate validation for the server",
				},
			},
		},
	},
}
