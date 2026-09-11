// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/clickhousedb/connection"
	"go.mondoo.com/mql/providers/clickhousedb/provider"
)

var Config = plugin.Provider{
	Name: "clickhousedb",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "clickhousedb",
	ID:      "go.mondoo.com/mql/providers/clickhousedb",
	Version: "13.0.2",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.2"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "clickhousedb",
			Use:   "clickhousedb [host]",
			Short: "a ClickHouse server",
			Long: `Use the clickhousedb provider to query a ClickHouse database server.

The provider connects over the ClickHouse native protocol and runs read-only
queries against the system tables (system.users, system.roles, system.grants,
and related) to inventory the server version, its users, roles, grants, settings
profiles, quotas, and clusters, so you can audit the server's security posture.

Examples:
  cnspec shell clickhousedb db.contoso.com --user auditor --ask-pass
  cnspec scan clickhousedb db.contoso.com --user auditor --ask-pass --tls
`,
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "ClickHouse hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "9000",
					Desc:    "ClickHouse native protocol port",
				},
				{
					Long:    "database",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Database to connect to (default \"default\")",
				},
				{
					Long:    "user",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User name to authenticate as (default \"default\")",
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
					Long:    "tls-insecure",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Skip TLS certificate verification (testing only)",
				},
			},
		},
	},
}
