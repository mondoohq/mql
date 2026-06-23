// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/gusto/provider"
)

var Config = plugin.Provider{
	Name:            "gusto",
	ID:              "go.mondoo.com/mql/providers/gusto",
	Version:         "13.0.0",
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "gusto",
			Use:   "gusto",
			Short: "a Gusto company",
			Long: `Use the gusto provider to query the company profile, workforce,
and administrators of a Gusto-managed company.

Authentication is via a Gusto API token. Pass --token or set the
GUSTO_API_TOKEN environment variable.

Examples:
  cnspec shell gusto --token <api-token>
  cnspec scan gusto --token <api-token>
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Gusto API token",
				},
				{
					Long:    "api-base",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Override the Gusto API base URL (e.g., https://api.gusto-demo.com)",
				},
				{
					Long:    "api-version",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Override the X-Gusto-API-Version header",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=gusto"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"company": nil,
			},
		},
	},
}
