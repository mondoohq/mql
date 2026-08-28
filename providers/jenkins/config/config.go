// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jenkins/connection"
	"go.mondoo.com/mql/providers/jenkins/provider"
)

var Config = plugin.Provider{
	Name:            "jenkins",
	ID:              "go.mondoo.com/mql/providers/jenkins",
	Version:         "13.0.0",
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "jenkins",
			Use:   "jenkins",
			Short: "a Jenkins controller",
			Long: fmt.Sprintf(`
Use the jenkins provider to query the security configuration, installed
plugins, jobs, agents, and stored credential metadata of a Jenkins
controller.

Authentication uses a Jenkins username paired with a per-user API token
over HTTP Basic auth:

  mql shell jenkins --url https://jenkins.example.com --user <user> --token <token>

You can also use the default environment variables '%s', '%s',
and '%s' to provide your connection details.
`,
				connection.JENKINS_URL_VAR,
				connection.JENKINS_USER_VAR,
				connection.JENKINS_TOKEN_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_URL,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Jenkins base URL (e.g. https://jenkins.example.com)",
				},
				{
					Long:    connection.OPTION_USER,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Jenkins username",
				},
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Jenkins API token",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}
