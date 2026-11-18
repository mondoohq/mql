// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
	"go.mondoo.com/mql/providers/codesphere/provider"
)

var Config = plugin.Provider{
	Name: "codesphere",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	// A connection reports the concrete kind through ConnectRes.Root.
	Root:    "codesphere",
	ID:      "go.mondoo.com/mql/providers/codesphere",
	Version: "13.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "codesphere",
			Use:   "codesphere",
			Short: "a Codesphere installation",
			Long: `Use the codesphere provider to query the organizations, resource groups, and workspaces of a Codesphere installation, on the Codesphere cloud or a Private Cloud.

Examples:
  cnspec shell codesphere --token <api_token>
  cnspec scan codesphere --token <api_token>
  cnspec scan codesphere --token <api_token> --resource-group <resource_group_id>
  cnspec scan codesphere --token <api_token> --api https://codesphere.example.com/api

Notes:
  If you set the CS_TOKEN environment variable, you can omit the token flag.
  The API URL defaults to the Codesphere cloud, or CS_API when set.
`,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryOrganizations,
				connection.DiscoveryResourceGroups,
				connection.DiscoveryWorkspaces,
			},
			Flags: []plugin.Flag{
				{
					Long: "token",
					Type: plugin.FlagType_String,
					Desc: "Codesphere API token (or set CS_TOKEN)",
				},
				{
					Long: "api",
					Type: plugin.FlagType_String,
					Desc: "URL of the Codesphere API (or set CS_API), default " + connection.DefaultAPIURL,
				},
				{
					Long: "org",
					Type: plugin.FlagType_String,
					Desc: "Restrict the scan to one organization ID (or set CS_ORG_ID)",
				},
				{
					Long:  "resource-group",
					Short: "G",
					Type:  plugin.FlagType_String,
					Desc:  "Restrict the scan to one resource group ID (or set CS_RESOURCE_GROUP_ID)",
				},
			},
		},
	},
}
