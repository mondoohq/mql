// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jumpcloud/connection"
	"go.mondoo.com/mql/providers/jumpcloud/provider"
)

var Config = plugin.Provider{
	Name: "jumpcloud",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "jumpcloud",
	ID:      "go.mondoo.com/mql/providers/jumpcloud",
	Version: "13.0.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "jumpcloud",
			Use:   "jumpcloud",
			Short: "a JumpCloud organization",
			Long: `Use the jumpcloud provider to query the users, systems, groups, applications,
and policies of a JumpCloud organization.

Authenticate with a JumpCloud API key. Multi-tenant (MSP) administrators also
pass the organization id the key should act on.

Examples:
  cnspec shell jumpcloud --api-key <api-key>
  cnspec scan jumpcloud --api-key <api-key> --org-id <org-id>

The API key can also be supplied through the JUMPCLOUD_API_KEY environment
variable, and the organization id through JUMPCLOUD_ORG_ID.
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "JumpCloud API key",
				},
				{
					Long:    "org-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "JumpCloud organization id (required for multi-tenant API keys)",
				},
			},
		},
	},
	Platforms: connection.Platforms,
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=jumpcloud"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"org": nil,
			},
		},
	},
}
