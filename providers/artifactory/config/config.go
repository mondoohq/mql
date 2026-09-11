// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"go.mondoo.com/mql/providers/artifactory/provider"
)

var Config = plugin.Provider{
	Name: "artifactory",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "artifactory",
	ID:      "go.mondoo.com/mql/providers/artifactory",
	Version: "13.1.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "artifactory",
			Use:   "artifactory [url]",
			Short: "a JFrog Artifactory instance",
			Long: `Use the artifactory provider to query the configuration of a JFrog Artifactory instance.

The URL is the JFrog platform base URL. A cloud instance is
https://<name>.jfrog.io, a self-hosted instance is the host the platform is
served on. The /artifactory suffix the web interface shows is accepted and
removed.

The credential is an access token or a legacy API key. Reading permission
targets, users, groups, tokens, and the instance configuration requires an
administrator, so a token issued for a normal account reports those as errors.

Examples:
  cnspec shell artifactory --url https://example.jfrog.io --token <access_token>
  cnspec scan artifactory --url https://artifactory.example.com --token <access_token>

Notes:
  If you set the ARTIFACTORY_URL environment variable, you can omit the url flag.
  If you set the ARTIFACTORY_TOKEN environment variable, you can omit the token flag.
`,
			MinArgs:   0,
			MaxArgs:   1,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "JFrog platform base URL (for example https://example.jfrog.io)",
				},
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Artifactory access token for authentication",
				},
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Artifactory API key for authentication, an alternative to the access token",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=artifactory"},
			Key:          "instance",
			Title:        "Instance",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
	},
}
