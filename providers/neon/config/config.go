// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/providers/neon/provider"
)

var Config = plugin.Provider{
	Name: "neon",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "neon",
	ID:      "go.mondoo.com/mql/providers/neon",
	Version: "13.1.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "neon",
			Use:   "neon",
			Short: "a Neon organization or account",
			Long: `Use the neon provider to query the configuration and security posture of your Neon organizations, projects, and branches.

The token is a Neon API key, created under Account settings > API keys. A
personal key reaches the projects your account owns; an organization key
reaches that organization's projects and its member roster.

Examples:
  cnspec shell neon --token <api_key>
  cnspec scan neon --token <api_key>
  cnspec scan neon --token <api_key> --organization <org_id>

Notes:
  If you set the NEON_API_KEY environment variable, you can omit the token flag.
`,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryOrganizations,
				connection.DiscoveryProjects,
			},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Neon API key for authentication",
				},
				{
					Long:    "organization",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Scope the scan to a single Neon organization (ID)",
				},
			},
		},
	},
}
