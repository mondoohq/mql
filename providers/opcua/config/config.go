// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/opcua/provider"
)

var Config = plugin.Provider{
	Name: "opcua",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "opcua",
	ID:      "go.mondoo.com/mql/providers/opcua",
	Version: "13.0.26",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.26"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "opcua",
			Use:   "opcua [--endpoint <endpoint>]",
			Short: "an OPC UA device",
			Long: `Use the opcua provider to query resources on an Open Platform Communications Unified Architecture (OPC UA) server or device. OPC UA is a protocol for machine-to-machine communication in industrial automation.

By default the provider connects with the strongest security the server offers and
falls back to weaker endpoints when a session cannot be established. Use the security
flags to pin a policy and mode, and to supply the client certificate a hardened server
expects.

Examples:
  cnspec shell opcua --endpoint opc.tcp://<host>:<port>
  cnspec scan opcua --endpoint opc.tcp://<host>:<port>
  cnspec scan opcua --endpoint opc.tcp://<host>:<port> --security-policy Basic256Sha256 --security-mode SignAndEncrypt --cert-file client.der --key-file client.key
  cnspec scan opcua --endpoint opc.tcp://<host>:<port> --username <user> --password <password>
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "endpoint",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "OPC UA endpoint URL of the OPC UA server in the format opc.tcp://<host>:<port>",
					Option:  plugin.FlagOption_Required,
				},
				{
					Long:    "security-policy",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Security policy to use: None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, or Aes256Sha256RsaPss (default: the strongest policy the server offers)",
				},
				{
					Long:    "security-mode",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Message security mode to use: None, Sign, or SignAndEncrypt (default: the strongest mode the server offers)",
				},
				{
					Long:    "cert-file",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the PEM or DER encoded client certificate to present on the secure channel",
				},
				{
					Long:    "key-file",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the PEM or DER encoded private key that belongs to the client certificate",
				},
				{
					Long:    "username",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Username for OPC UA username and password authentication",
				},
				{
					Long:        "password",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Password for OPC UA username and password authentication",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
			},
		},
	},
}
