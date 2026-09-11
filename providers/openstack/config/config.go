// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openstack/connection"
	"go.mondoo.com/mql/providers/openstack/provider"
)

var Config = plugin.Provider{
	Name: "openstack",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "openstack",
	ID:      "go.mondoo.com/mql/providers/openstack",
	Version: "13.9.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.9.1"},
	},
	Platforms:       connection.Platforms,
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "openstack",
			Use:   "openstack",
			Short: "an OpenStack project",
			Long: `
Use the openstack provider to query Keystone, Nova, and Neutron resources
in an OpenStack project.

Authentication options (in priority order):
  1. CLI flags (--auth-url, --username, --password, --project-name, ...)
  2. --cloud <name> to select a clouds.yaml entry
  3. OS_* environment variables

Application credentials are also supported via --application-credential-id
and --application-credential-secret.

Examples:
  cnspec shell openstack --cloud <CLOUDS-YAML-ENTRY>
  cnspec scan openstack --auth-url <KEYSTONE-URL> --username <USERNAME> --password <PASSWORD> --project-name <PROJECT-NAME>
  cnspec scan openstack --auth-url <KEYSTONE-URL> --application-credential-id <ID> --application-credential-secret <SECRET>
  cnspec scan openstack --cloud <CLOUDS-YAML-ENTRY> --discover security-groups
`,
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoverySecurityGroups,
			},
			Flags: []plugin.Flag{
				{Long: connection.OPTION_CLOUD, Type: plugin.FlagType_String, Desc: "clouds.yaml entry to use"},
				{Long: connection.OPTION_AUTH_URL, Type: plugin.FlagType_String, Desc: "Keystone auth URL (env: OS_AUTH_URL)"},
				{Long: connection.OPTION_USERNAME, Type: plugin.FlagType_String, Desc: "username (env: OS_USERNAME)"},
				{Long: connection.OPTION_PASSWORD, Type: plugin.FlagType_String, Desc: "password (env: OS_PASSWORD)"},
				{Long: connection.OPTION_PROJECT_NAME, Type: plugin.FlagType_String, Desc: "project name (env: OS_PROJECT_NAME)"},
				{Long: connection.OPTION_PROJECT_ID, Type: plugin.FlagType_String, Desc: "project ID (env: OS_PROJECT_ID)"},
				{Long: connection.OPTION_USER_DOMAIN_NAME, Type: plugin.FlagType_String, Desc: "user domain name (env: OS_USER_DOMAIN_NAME)"},
				{Long: connection.OPTION_USER_DOMAIN_ID, Type: plugin.FlagType_String, Desc: "user domain ID (env: OS_USER_DOMAIN_ID)"},
				{Long: connection.OPTION_PROJECT_DOMAIN_NAME, Type: plugin.FlagType_String, Desc: "project domain name (env: OS_PROJECT_DOMAIN_NAME)"},
				{Long: connection.OPTION_PROJECT_DOMAIN_ID, Type: plugin.FlagType_String, Desc: "project domain ID (env: OS_PROJECT_DOMAIN_ID)"},
				{Long: connection.OPTION_REGION, Type: plugin.FlagType_String, Desc: "region (env: OS_REGION_NAME)"},
				{Long: connection.OPTION_APPLICATION_CREDENTIAL_ID, Type: plugin.FlagType_String, Desc: "application credential ID (env: OS_APPLICATION_CREDENTIAL_ID)"},
				{Long: connection.OPTION_APPLICATION_CREDENTIAL_NAME, Type: plugin.FlagType_String, Desc: "application credential name (env: OS_APPLICATION_CREDENTIAL_NAME)"},
				{Long: connection.OPTION_APPLICATION_CREDENTIAL_SECRET, Type: plugin.FlagType_String, Desc: "application credential secret (env: OS_APPLICATION_CREDENTIAL_SECRET)"},
				{Long: connection.OPTION_INSECURE, Type: plugin.FlagType_Bool, Desc: "skip TLS certificate verification"},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=openstack"},
			Key:          "project",
			Title:        "Project",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
	},
}
