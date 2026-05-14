// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/rippling/provider"
)

var Config = plugin.Provider{
	Name:            "rippling",
	ID:              "go.mondoo.com/mql/providers/rippling",
	Version:         "13.0.0",
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "rippling",
			Use:   "rippling",
			Short: "a Rippling company",
			Long: `Use the rippling provider to query the company profile, workforce, and
org structure of a Rippling-managed company.

Authentication uses the Rippling OAuth 2.0 flow. Register an app in the
Rippling developer portal, complete the authorization-code grant once to
obtain a refresh token, then supply the client ID, client secret, and
refresh token via flags or the RIPPLING_CLIENT_ID, RIPPLING_CLIENT_SECRET,
and RIPPLING_REFRESH_TOKEN environment variables.

Examples:
  cnspec shell rippling --client-id <id> --client-secret <secret> --refresh-token <token>
  cnspec scan rippling --client-id <id> --client-secret <secret> --refresh-token <token>
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Rippling OAuth client ID",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Rippling OAuth client secret",
				},
				{
					Long:    "refresh-token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Rippling OAuth refresh token",
				},
				{
					Long:    "api-base",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Override the Rippling API base URL (default https://api.rippling.com)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=rippling"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"company": nil,
			},
		},
	},
}
