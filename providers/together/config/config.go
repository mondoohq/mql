// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/together/connection"
	"go.mondoo.com/mql/providers/together/provider"
)

var Config = plugin.Provider{
	Name: "together",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "together",
	ID:      "go.mondoo.com/mql/providers/together",
	Version: "13.0.14",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.14"},
	},
	Platforms:       provider.Platforms,
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "together",
			Use:   "together",
			Short: "a Together AI account",
			Long: `Use the together provider to query models, fine-tuning jobs, dedicated
endpoint deployments, and uploaded files in a Together AI account.

Examples:
  mql shell together --token <api-key>
  mql shell together   # uses TOGETHER_API_KEY env var

Notes:
  The provider queries the Together AI REST API at https://api.together.ai/v1.
  An API key is required; generate one at https://api.together.ai/settings/api-keys.
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OptionToken,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Together AI API key (or set TOGETHER_API_KEY env var)",
				},
				{
					Long:    connection.OptionBaseURL,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "API base URL (default: https://api.together.ai/v1)",
				},
				{
					Long:    connection.OptionProject,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Together AI project ID (e.g. proj_...)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=ai", "provider=together"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"account": nil,
			},
		},
	},
}
