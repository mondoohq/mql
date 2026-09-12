// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/redisdb/connection"
	"go.mondoo.com/mql/providers/redisdb/provider"
)

var Config = plugin.Provider{
	Name: "redisdb",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "redisdb",
	ID:      "go.mondoo.com/mql/providers/redisdb",
	Version: "13.0.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.3"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "redisdb",
			Use:   "redisdb [host]",
			Short: "a Redis or Valkey server",
			Long: `Use the redisdb provider to query a Redis or Valkey server.

The provider connects to the server and runs read-only commands (INFO,
CONFIG GET, and the ACL commands) to inventory the server's version and mode,
its network and authentication posture, its access-control users, and its
durability configuration, so you can audit the server's security posture.

Examples:
  cnspec shell redisdb localhost --ask-pass
  cnspec scan redisdb redis.contoso.com --user auditor --ask-pass --tls
`,
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Redis/Valkey hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "6379",
					Desc:    "Redis/Valkey TCP port",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "ACL user name to authenticate as (Redis 6+); omit for legacy password auth",
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
					Long:    "database",
					Type:    plugin.FlagType_Int,
					Default: "0",
					Desc:    "Logical database index to select",
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
