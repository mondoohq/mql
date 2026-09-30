// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/firebase/provider"
)

var Config = plugin.Provider{
	Name:    "firebase",
	ID:      "go.mondoo.com/mql/providers/firebase",
	Version: "14.0.0",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root: "firebase.project",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "14.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "firebase",
			Use:   "firebase [domain]",
			Short: "a Firebase project",
			Long: `Use the firebase provider to check Firebase projects for security misconfigurations via public endpoints.

Examples:
  mql shell firebase --project-id my-project --api-key AIzaSy...
  mql shell firebase --domain myapp.firebaseapp.com
  mql shell firebase myapp.web.app
  mql run firebase --project-id my-project -c "firebase.project.realtimeDatabase { publiclyReadable }"

Notes:
  - Provide --project-id and --api-key for direct checks, or --domain to auto-discover them.
  - A positional argument is treated as a domain.
  - --domain always enables the hosting probes, also when --project-id is given; discovery only runs when --project-id is absent.
  - All checks are read-only and use only public HTTP endpoints.
`,
			MinArgs: 0,
			MaxArgs: 1,
			Flags: []plugin.Flag{
				{
					Long:    "project-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Firebase project ID",
				},
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Firebase API key (web API key)",
				},
				{
					Long:    "domain",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Domain to scan for Firebase configuration",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "category=firebase"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"project": nil,
			},
		},
	},
}
