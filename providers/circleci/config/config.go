// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/circleci/connection"
	"go.mondoo.com/mql/providers/circleci/provider"
)

var Config = plugin.Provider{
	Name:            "circleci",
	ID:              "go.mondoo.com/mql/providers/circleci",
	Version:         "13.0.0",
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "circleci",
			Use:   "circleci",
			Short: "a CircleCI account",
			Long: fmt.Sprintf(`
Use the circleci provider to query organizations, projects, contexts, and
checkout keys of a CircleCI account.

Authentication uses a personal or project API token:

  cnspec shell circleci --token <token>

You can also use the default environment variable '%s' to provide your
token.
`,
				connection.CIRCLECI_TOKEN_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "CircleCI API token",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}
