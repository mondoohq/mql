// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

var Config = plugin.Provider{
	Name:       "core",
	ID:         "go.mondoo.com/mql/providers/core",
	Version:    mql.GetVersion(),
	Connectors: []plugin.Connector{},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=other"},
			Key:          "platform",
			Title:        "Other Platform",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
	},
}
