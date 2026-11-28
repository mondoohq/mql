// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/yugabyte/connection"
	"go.mondoo.com/mql/providers/yugabyte/provider"
)

var Config = plugin.Provider{
	Name: "yugabyte",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "yugabyte",
	ID:      "go.mondoo.com/mql/providers/yugabyte",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:    "yugabyte",
			Use:     "yugabyte [host]",
			Short:   "a YugabyteDB cluster",
			MaxArgs: 1,
			Long: `Use the yugabyte provider to query a YugabyteDB cluster.

The provider connects to one node of the cluster. It reads the cluster, its
masters and tablet servers, and their flags from the master and tablet server
HTTP APIs, and roles, settings, authentication rules, and privileges over
YSQL and YCQL with read-only queries. Connect as a YSQL superuser to read
everything. The password can also come from the YUGABYTE_PASSWORD environment
variable; when YCQL uses other credentials than YSQL, give them with
--ycql-user and --ycql-password (or YUGABYTE_YCQL_PASSWORD).

The node's own HTTP APIs are read at the host and the configured ports, so a
node behind published container ports works; every other server is read at
the address the master reports for it.

Examples:
  mql shell yugabyte localhost
  cnspec scan yugabyte db.example.com --user auditor --ask-pass --sslrootcert ca.crt --ycql-tls
  cnspec scan yugabyte 127.0.0.1 --master-http-port 17000 --tserver-http-port 19000 --ysql-port 15433 --ycql-port 19042
`,
			Flags: []plugin.Flag{
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Hostname or IP address of a YugabyteDB node",
				},
				{
					Long:    "master-http-port",
					Type:    plugin.FlagType_Int,
					Default: "7000",
					Desc:    "HTTP port of the master on the host",
				},
				{
					Long:    "tserver-http-port",
					Type:    plugin.FlagType_Int,
					Default: "9000",
					Desc:    "HTTP port of the tablet server on the host",
				},
				{
					Long:    "ysql-port",
					Type:    plugin.FlagType_Int,
					Default: "5433",
					Desc:    "YSQL port",
				},
				{
					Long:    "ycql-port",
					Type:    plugin.FlagType_Int,
					Default: "9042",
					Desc:    "YCQL port",
				},
				{
					Long:    "database",
					Type:    plugin.FlagType_String,
					Default: "yugabyte",
					Desc:    "YSQL database to connect to",
				},
				{
					Long:    "user",
					Short:   "u",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User to authenticate as (default yugabyte for YSQL, cassandra for YCQL)",
				},
				{
					Long:        "password",
					Short:       "p",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Set the connection password (or YUGABYTE_PASSWORD)",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:    "ycql-user",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User to authenticate to YCQL as, when it differs from --user",
				},
				{
					Long:        "ycql-password",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "YCQL password, when it differs from --password (or YUGABYTE_YCQL_PASSWORD)",
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
					Long:    "sslmode",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "YSQL TLS mode: disable, allow, prefer, require, verify-ca, or verify-full (default prefer, or verify-full with --sslrootcert)",
				},
				{
					Long:    "sslrootcert",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the CA certificate that signed the server certificates, trusted for YSQL, YCQL, and HTTPS",
				},
				{
					Long:    "sslcert",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to a client certificate for YSQL, YCQL, and HTTPS",
				},
				{
					Long:    "sslkey",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the client certificate's private key",
				},
				{
					Long:    "ycql-tls",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Connect to YCQL over TLS (implied by --sslrootcert)",
				},
				{
					Long:    "https",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Use HTTPS for the master and tablet server HTTP APIs",
				},
				{
					Long:    "tls-insecure",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Skip server certificate verification for YCQL and HTTPS",
				},
			},
		},
	},
}
