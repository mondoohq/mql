// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iru/connection"
	"go.mondoo.com/mql/providers/iru/provider"
)

var Config = plugin.Provider{
	Name: "iru",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "iru",
	ID:      "go.mondoo.com/mql/providers/iru",
	Version: "13.0.7",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.7"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "iru",
			Use:   "iru",
			Short: "an Iru tenant",
			Long: `Use the Iru provider to query an Iru (formerly Kandji) tenant.

To access the Iru API, you need your tenant subdomain and a bearer token
issued in the Iru admin console. The subdomain is the first label of your
tenant API host: pass "mondoo" for a tenant served at
https://mondoo.api.kandji.io. The token's per-endpoint permission flags
determine which sub-resources will return data.

Examples:
  mql shell iru --subdomain mondoo --token <api-token>
  cnspec scan iru --subdomain mondoo --token <api-token>
`,
			Flags: []plugin.Flag{
				{
					Long:    "subdomain",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Iru tenant subdomain (e.g. mondoo for https://mondoo.api.kandji.io)",
				},
				{
					Long:        "token",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Iru API bearer token",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=iru"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"api": nil,
			},
		},
	},
}
