// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cockroachdb/connection"
	"go.mondoo.com/mql/providers/cockroachdb/provider"
)

var Config = plugin.Provider{
	Name: "cockroachdb",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "cockroachdb",
	ID:      "go.mondoo.com/mql/providers/cockroachdb",
	Version: "14.0.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:    "cockroachdb",
			Use:     "cockroachdb [host]",
			Short:   "a CockroachDB cluster",
			MaxArgs: 1,
			Long: `Use the cockroachdb provider to query a CockroachDB cluster.

The provider connects to any node of the cluster over SQL and runs read-only
queries against crdb_internal, system tables, and SHOW statements to inventory
cluster settings, host-based authentication rules, roles, databases and their
privileges, nodes with their certificates and stores, and backup schedules.
Connect as a member of the admin role to read everything.

Examples:
  cnspec shell cockroachdb localhost --certs-dir certs
  cnspec scan cockroachdb db.contoso.com --user auditor --ask-pass --sslmode verify-full --sslrootcert ca.crt
`,
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "CockroachDB hostname or IP address",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_Int,
					Default: "26257",
					Desc:    "CockroachDB SQL port",
				},
				{
					Long:    "database",
					Type:    plugin.FlagType_String,
					Default: "defaultdb",
					Desc:    "Database to connect to",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "root",
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
					Long:    "certs-dir",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "CockroachDB certificate directory with ca.crt and client.<user>.crt/.key; implies --sslmode verify-full",
				},
				{
					Long:    "sslmode",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "TLS mode: disable, allow, prefer, require, verify-ca, or verify-full (default prefer, or verify-full with --certs-dir)",
				},
				{
					Long:    "sslrootcert",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the trusted CA certificate for TLS verification",
				},
				{
					Long:    "sslcert",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the client certificate for TLS client authentication",
				},
				{
					Long:    "sslkey",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the client private key for TLS client authentication",
				},
			},
		},
	},
}
