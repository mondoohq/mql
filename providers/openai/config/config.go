// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openai/connection"
	"go.mondoo.com/mql/providers/openai/provider"
)

var Config = plugin.Provider{
	Name: "openai",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "openai",
	ID:      "go.mondoo.com/mql/providers/openai",
	Version: "13.1.3",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.3"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "openai",
			Use:   "openai",
			Short: "an OpenAI account",
			Long: `Use the openai provider to query project, organization, and API key configuration
in an OpenAI account.

Examples:
  cnspec shell openai --token <API-KEY>
  cnspec scan openai --token <ADMIN-API-KEY> --organization <ORG-ID>
  cnspec scan openai --token <PROJECT-API-KEY> --admin-token <ADMIN-API-KEY>
  cnspec scan openai --project <PROJECT-ID>

Notes:
  If you set the OPENAI_API_KEY environment variable, you can omit the token flag. Both
  project keys (sk-proj-...) and admin keys (sk-admin-...) are accepted and detected
  automatically; organization resources require an admin key.

  Pass both keys, with the admin key in --admin-token (or OPENAI_ADMIN_KEY), to reach
  resources that need one credential for the object and the other for its governance,
  such as which projects a fine-tuning checkpoint is shared into.
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long: "token",
					Type: plugin.FlagType_String,
					Desc: "OpenAI API key — project key (sk-proj-...) or admin key (sk-admin-...), auto-detected",
				},
				{
					Long: "admin-token",
					Type: plugin.FlagType_String,
					Desc: "OpenAI admin API key (sk-admin-...) to use alongside --token (or set OPENAI_ADMIN_KEY env var)",
				},
				{
					Long: "organization",
					Type: plugin.FlagType_String,
					Desc: "OpenAI organization ID (or set OPENAI_ORG_ID env var)",
				},
				{
					Long: "project",
					Type: plugin.FlagType_String,
					Desc: "OpenAI project ID (or set OPENAI_PROJECT_ID env var)",
				},
				{
					Long: "base-url",
					Type: plugin.FlagType_String,
					Desc: "OpenAI API base URL for custom endpoints (or set OPENAI_BASE_URL env var)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=ai", "provider=openai"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"account": nil,
			},
		},
	},
}
