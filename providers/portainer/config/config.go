// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/providers/portainer/provider"
)

var Config = plugin.Provider{
	Name: "portainer",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "portainer",
	ID:      "go.mondoo.com/mql/providers/portainer",
	Version: "13.1.9",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.9"},
	},
	Maturity:        resources.MaturityExperimental,
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "portainer",
			Use:   "portainer HOST",
			Short: "a Portainer instance",
			Long: `Use the portainer provider to audit the control-plane security posture of a
Portainer instance: authentication settings, the container-security flags that
govern what regular users may do, user and team RBAC, and the environments
(endpoints) Portainer manages.

The instance address is a positional argument. It may be a bare host, host:port,
or a full URL; https is assumed when no scheme is given.

Examples:
  cnspec scan portainer https://portainer.example.com --access-token ptr_xxx
  cnspec shell portainer portainer.example.com:9443 --access-token ptr_xxx

Use --insecure (-k) to skip TLS verification for instances with self-signed
certificates.

The address and access token can also be supplied through environment variables:

  PORTAINER_ADDRESS, PORTAINER_ACCESS_TOKEN
`,
			MinArgs: 0,
			MaxArgs: 1,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryEnvironments,
				connection.DiscoveryDocker,
				connection.DiscoveryKubernetes,
				connection.DiscoveryEdge,
			},
			Flags: []plugin.Flag{
				{
					Long: "address",
					Type: plugin.FlagType_String,
					Desc: "Portainer instance address, e.g. https://portainer.example.com (env: PORTAINER_ADDRESS)",
				},
				{
					Long: "access-token",
					Type: plugin.FlagType_String,
					Desc: "Portainer access token, format ptr_xxx (env: PORTAINER_ACCESS_TOKEN)",
				},
				{
					Long:        "insecure",
					Short:       "k",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Skip TLS certificate verification",
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=virtualization", "provider=portainer"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"instance":    nil,
				"environment": nil,
			},
		},
	},
}
