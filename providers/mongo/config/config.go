// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mongo/connection"
	"go.mondoo.com/mql/providers/mongo/provider"
)

var Config = plugin.Provider{
	Name: "mongo",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "mongo",
	ID:      "go.mondoo.com/mql/providers/mongo",
	Version: "13.1.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "mongo",
			Use:   "mongo [host]",
			Short: "a self-hosted MongoDB server",
			Long: `Use the mongo provider to query a self-hosted MongoDB server.

The provider connects to a MongoDB server and runs read-only admin commands
(buildInfo, getCmdLineOpts, getParameter, usersInfo, rolesInfo) to inventory
the server's configuration, users, roles, and databases so you can audit its
security posture (the CIS MongoDB benchmark).

For MongoDB Atlas (the managed service), use the mongodbatlas provider instead.

Examples:
  cnspec shell mongo db.contoso.com --user admin --ask-pass
  cnspec scan mongo mongodb://admin@db.contoso.com:27017 --ask-pass
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
					Desc:    "MongoDB hostname or IP address (or a mongodb:// connection string)",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "27017",
					Desc:    "MongoDB TCP port",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User to authenticate as",
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
					Long:    "auth-db",
					Type:    plugin.FlagType_String,
					Default: "admin",
					Desc:    "Authentication database (default admin)",
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
					Desc:    "Skip TLS certificate validation",
				},
			},
		},
	},
}
