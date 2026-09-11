// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/claude/connection"
	"go.mondoo.com/mql/providers/claude/provider"
)

var Config = plugin.Provider{
	Name: "claude",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "claude",
	ID:      "go.mondoo.com/mql/providers/claude",
	Version: "13.1.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.3"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "claude",
			Use:   "claude",
			Short: "a Claude AI platform account",
			Long: `Use the claude provider to query organization, workspace, API key, and service account
configuration in a Claude AI platform account.

Examples:
  cnspec shell claude --token <API-KEY>
  cnspec scan claude --admin-token <ADMIN-API-KEY> --discover organization
  cnspec scan claude --admin-token <ADMIN-API-KEY> --discover workspaces

Notes:
  If you set the ANTHROPIC_API_KEY environment variable, you can omit the token flag.

  Organization and workspace resources require an Admin API key. Supply it with
  --admin-token or by setting the ANTHROPIC_ADMIN_API_KEY environment variable.
`,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryOrg,
				connection.DiscoveryWorkspaces,
			},
			Flags: []plugin.Flag{
				{
					Long: "token",
					Type: plugin.FlagType_String,
					Desc: "Claude API key (or set ANTHROPIC_API_KEY env var)",
				},
				{
					Long: "admin-token",
					Type: plugin.FlagType_String,
					Desc: "Claude Admin API key for organization resources (or set ANTHROPIC_ADMIN_API_KEY env var)",
				},
				{
					Long: "identity-token-file",
					Type: plugin.FlagType_String,
					Desc: "Path to OIDC identity token file for Workload Identity Federation",
				},
				{
					Long: "federation-rule-id",
					Type: plugin.FlagType_String,
					Desc: "Anthropic federation rule ID (fdrl_...) for WIF authentication",
				},
				{
					Long: "organization-id",
					Type: plugin.FlagType_String,
					Desc: "Anthropic organization ID for WIF authentication (or set ANTHROPIC_ORGANIZATION_ID env var)",
				},
				{
					Long: "service-account-id",
					Type: plugin.FlagType_String,
					Desc: "Anthropic service account ID (svac_...) for WIF authentication",
				},
				{
					Long: "workspace-id",
					Type: plugin.FlagType_String,
					Desc: "Anthropic workspace ID (wrkspc_...) to scope WIF token to a specific workspace",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=ai", "provider=claude"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"api": nil,
			},
		},
	},
}
