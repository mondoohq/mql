// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/slack/connection"
	"go.mondoo.com/mql/providers/slack/provider"
)

var Config = plugin.Provider{
	Name: "slack",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "slack",
	ID:      "go.mondoo.com/mql/providers/slack",
	Version: "13.1.23",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.23"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "slack",
			Use:   "slack",
			Short: "a Slack team",
			Long: `Use the slack provider to query resources in a Slack team.

Examples:
  cnspec shell slack --token <api-token>
  cnspec scan slack --team-id <team-id> --token <api-token>
`,
			MinArgs:   0,
			MaxArgs:   0,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Slack API token (To learn more, read https://mondoo.com/docs/cnspec/saas/slack)",
				},
				{
					Long:    "team-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Team ID (required if the token is an org token)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=slack"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"team": nil,
			},
		},
	},
}
