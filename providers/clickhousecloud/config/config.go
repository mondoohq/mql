// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/clickhousecloud/connection"
	"go.mondoo.com/mql/providers/clickhousecloud/provider"
)

var Config = plugin.Provider{
	Name: "clickhousecloud",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "clickhousecloud",
	ID:      "go.mondoo.com/mql/providers/clickhousecloud",
	Version: "13.0.2",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.2"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "clickhousecloud",
			Use:   "clickhousecloud",
			Short: "a ClickHouse Cloud organization",
			Long: `Use the clickhousecloud provider to query the ClickHouse Cloud control-plane API.

The provider authenticates with an organization API key (key id + secret) and
inventories the organization's services, their IP access lists and endpoints,
API keys, and members, so you can audit the organization's security posture,
for example services reachable from any IP or API keys that never expire.

Examples:
  cnspec shell clickhousecloud --organization-id ORG_ID --api-key KEY_ID --ask-secret
`,
			Flags: []plugin.Flag{
				{
					Long:    "organization-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "ClickHouse Cloud organization ID",
				},
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "ClickHouse Cloud API key id",
				},
				{
					Long:        "api-secret",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "ClickHouse Cloud API key secret",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:        "ask-secret",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for the API key secret",
					ConfigEntry: "-",
				},
				{
					Long:    "api-url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Override the ClickHouse Cloud API base URL",
				},
			},
		},
	},
}
