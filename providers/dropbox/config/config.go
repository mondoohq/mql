// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/dropbox/connection"
	"go.mondoo.com/mql/providers/dropbox/provider"
)

var Config = plugin.Provider{
	Name: "dropbox",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "dropbox",
	ID:      "go.mondoo.com/mql/providers/dropbox",
	Version: "13.0.2",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.2"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "dropbox",
			Use:   "dropbox",
			Short: "a Dropbox Business team",
			Long: fmt.Sprintf(`
Use the dropbox provider to query the members, groups, linked devices, and
linked third-party apps of a Dropbox Business team.

Authentication uses a Dropbox Business team access token, issued to a
Dropbox Business App with team-level (not per-user) scoped access:

  cnspec shell dropbox --token <team-scoped-access-token>

You can also use the default environment variable '%s' to provide the
token.
`,
				connection.DROPBOX_TEAM_TOKEN_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Dropbox Business team access token",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}
