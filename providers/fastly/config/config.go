// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/fastly/connection"
	"go.mondoo.com/mql/providers/fastly/provider"
)

var Config = plugin.Provider{
	Name: "fastly",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "fastly",
	ID:      "go.mondoo.com/mql/providers/fastly",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "fastly",
			Use:   "fastly",
			Short: "a Fastly account",
			Long: `Use the fastly provider to query the services, domains, backends, TLS
certificates, and users of a Fastly account through the Fastly API.

Create an API token under Account > Personal API tokens. A read-only token with
global scope is enough for every resource this provider exposes.

Examples:
  cnspec shell fastly --api-token <token>
  cnspec scan fastly --api-token <token>

Notes:
  If you set the FASTLY_API_KEY environment variable, you can omit the
  --api-token flag. Set FASTLY_API_URL to reach a private API instance.
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "api-token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Fastly API token",
				},
				{
					Long:    "base-url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Base URL of the Fastly API, for a private instance (default https://api.fastly.com)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=fastly"},
			Key:          "account",
			Title:        "Account",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
	},
}
