// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/n8n/connection"
	"go.mondoo.com/mql/providers/n8n/provider"
)

var Config = plugin.Provider{
	Name: "n8n",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "n8n",
	ID:      "go.mondoo.com/mql/providers/n8n",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:    "n8n",
			Use:     "n8n [url]",
			Short:   "an n8n instance",
			MaxArgs: 1,
			Long: `Use the n8n provider to query the workflows, credentials, users, and security audit of an n8n instance through its Public API.

Create an API key under Settings > n8n API. Read access needs the workflow:list,
credential:list, user:list, tag:list, communityPackage:list, and
securityAudit:generate scopes.

Examples:
  cnspec shell n8n https://n8n.example.com --api-key <api_key>
  cnspec scan n8n https://n8n.example.com --api-key <api_key>

Notes:
  If you set the N8N_URL and N8N_API_KEY environment variables, you can omit the URL and the api-key flag.
`,
			Flags: []plugin.Flag{
				{
					Long:    "url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "URL of the n8n instance, for example https://n8n.example.com",
				},
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "n8n API key",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=n8n"},
			Key:          "instance",
			Title:        "Instance",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
	},
}
