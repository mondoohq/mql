// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/providers/databricks/provider"
)

var Config = plugin.Provider{
	Name:      "databricks",
	ID:        "go.mondoo.com/mql/providers/databricks",
	Version:   "13.3.1",
	Platforms: connection.Platforms,
	ConnectionTypes: []string{
		provider.DefaultConnectionType,
	},
	Connectors: []plugin.Connector{
		{
			Name:  "databricks",
			Use:   "databricks",
			Short: "a Databricks account or workspace",
			Long: `Use the databricks provider to query the security posture of a Databricks
account and its workspaces.

Connecting to the account console (OAuth M2M service principal) discovers every
workspace as a child asset. You can also connect a single workspace directly
with a personal access token.

Examples:
  cnspec shell databricks --account-id <account-id> --client-id <id> --client-secret <secret>
  cnspec shell databricks --host <workspace-url> --token <pat>

Notes:
  Set DATABRICKS_ACCOUNT_ID, DATABRICKS_HOST, DATABRICKS_CLIENT_ID,
  DATABRICKS_CLIENT_SECRET, or DATABRICKS_TOKEN to omit the matching flags.

  For Azure- or GCP-hosted Databricks, override --host with the account console
  host (accounts.azuredatabricks.net or accounts.gcp.databricks.com).
`,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryWorkspaces,
			},
			Flags: []plugin.Flag{
				{
					Long:    "account-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Databricks account id (connects to the account console and discovers workspaces)",
				},
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Databricks host (account console host, or a workspace URL for a direct connect)",
				},
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "OAuth M2M service principal client id",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "OAuth M2M service principal client secret",
				},
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Personal access token for a direct workspace connect",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=databricks"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"account": {
					PathSegments: []string{"kind=account"},
					Key:          "account",
					Title:        "Account",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": {
							Key:   "workspace",
							Title: "Workspace",
							Values: map[string]*inventory.AssetUrlBranch{
								"*": nil,
							},
						},
					},
				},
				"workspace": {
					PathSegments: []string{"kind=workspace"},
					Key:          "workspace",
					Title:        "Workspace",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": nil,
					},
				},
			},
		},
	},
}
