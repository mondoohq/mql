// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
	"go.mondoo.com/mql/v13/providers/bitbucket/provider"
)

var Config = plugin.Provider{
	Name:            "bitbucket",
	ID:              "go.mondoo.com/mql/providers/bitbucket",
	Version:         "13.0.0",
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "bitbucket",
			Use:   "bitbucket",
			Short: "a Bitbucket Cloud workspace",
			Long: fmt.Sprintf(`
Use the bitbucket provider to query workspaces, projects, repositories,
branch restrictions, deploy keys, and the members and groups of a Bitbucket
Cloud workspace.

Authentication uses either a workspace/repository Access Token:

  cnspec shell bitbucket --workspace <workspace-slug> --token <token>

or a username and App Password:

  cnspec shell bitbucket --workspace <workspace-slug> --username <user> --app-password <password>

You can also use the default environment variables '%s', '%s', '%s', and
'%s' to provide your workspace and credentials.
`,
				connection.BITBUCKET_WORKSPACE_VAR,
				connection.BITBUCKET_USERNAME_VAR,
				connection.BITBUCKET_TOKEN_VAR,
				connection.BITBUCKET_APP_PASSWORD_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_WORKSPACE,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitbucket workspace slug (e.g. acme-corp)",
				},
				{
					Long:    connection.OPTION_USERNAME,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitbucket username, required together with --app-password",
				},
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitbucket workspace or repository Access Token (Bearer auth)",
				},
				{
					Long:    connection.OPTION_APP_PASSWORD,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitbucket App Password, required together with --username (Basic auth)",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}
