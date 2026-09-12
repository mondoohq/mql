// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection"
	"go.mondoo.com/mql/providers/atlassian/connection/confluence"
	"go.mondoo.com/mql/providers/atlassian/provider"
)

var Config = plugin.Provider{
	Name: "atlassian",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	// A connection reports the concrete kind through ConnectRes.Root.
	Root:    "atlassian.admin.organization",
	ID:      "go.mondoo.com/mql/providers/atlassian",
	Version: "13.4.8",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.4.8"},
	},
	Platforms: connection.Platforms,
	ConnectionTypes: []string{
		provider.DefaultConnectionType,
		"jira",
		"admin",
		string(confluence.Confluence),
		"scim",
	},
	Connectors: []plugin.Connector{
		{
			Name:  "atlassian",
			Use:   "atlassian",
			Short: "an Atlassian Cloud Jira, Confluence or Bitbucket instance",
			Long: `Use the atlassian provider to query resources within Atlassian Cloud, including Jira, Confluence, and SCIM.

Available commands:
  admin                     Atlassian administrative instance
  jira                      Jira instance
  confluence                Confluence instance
  scim                      SCIM instance

Examples:
  cnspec shell atlassian admin --admin-token <token>
  cnspec shell atlassian jira --host <host> --user <user> --user-token <token>
  cnspec shell atlassian confluence --host <host> --user <user> --user-token <token>
  cnspec shell atlassian scim <directory-id> --scim-token <token>

Notes:
  If you set the ATLASSIAN_ADMIN_TOKEN environment variable, you can omit the admin-token flag. 
	
  If you set the ATLASSIAN_USER, ATLASSIAN_HOST, and ATLASSIAN_USER_TOKEN environment variables, you can omit the user, host, and user-token flags.

  For the SCIM token and the directory-id values: 
  Atlassian provides these values when you set up an identity provider.
`,
			MaxArgs:   2,
			Discovery: []string{connection.DiscoveryOrganization},
			Flags: []plugin.Flag{
				{
					Long:    "admin-token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Atlassian admin API token (used for Atlassian admin)",
				},
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Atlassian hostname (e.g. https://example.atlassian.net)",
				},
				{
					Long:    "user",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Atlassian user name (e.g. example@example.com)",
				},
				{
					Long:    "user-token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Atlassian user API token (used for Jira or Confluence)",
				},
				{
					Long:    "scim-token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Atlassian SCIM API token (used for SCIM)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=atlassian"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"admin":      nil,
				"confluence": nil,
				"jira":       nil,
				"scim":       nil,
			},
		},
	},
}
