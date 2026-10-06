// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
	"go.mondoo.com/mql/providers/exoscale/provider"
)

var Config = plugin.Provider{
	Name: "exoscale",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "exoscale",
	ID:      "go.mondoo.com/mql/providers/exoscale",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "exoscale",
			Use:   "exoscale",
			Short: "an Exoscale organization",
			Long: fmt.Sprintf(`
Use the exoscale provider to query compute instances, security groups, SKS
Kubernetes clusters, network load balancers, block storage, DBaaS services,
KMS keys, IAM, and DNS in an Exoscale organization.

Authenticate with an Exoscale API key and secret:

  cnspec shell exoscale --api-key EXO... --api-secret <secret>

You can also set the %s and %s environment variables.
Restrict the zones queried with --zones ch-gva-2,de-fra-1, and the
discovered resources by label with --filters labels=env=prod.
`, connection.EXOSCALE_API_KEY_VAR, connection.EXOSCALE_API_SECRET_VAR),
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryInstances,
				connection.DiscoverySecurityGroups,
				connection.DiscoverySksClusters,
				connection.DiscoveryNlbs,
				connection.DiscoveryDbaasServices,
			},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_API_KEY,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Exoscale API key (env: EXOSCALE_API_KEY)",
				},
				{
					Long:    connection.OPTION_API_SECRET,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Exoscale API secret (env: EXOSCALE_API_SECRET)",
				},
				{
					Long: connection.OPTION_ZONES,
					Type: plugin.FlagType_List,
					Desc: "Restrict the zones queried, for example ch-gva-2,de-fra-1 (env: EXOSCALE_ZONES)",
				},
				{
					Long:    "filters",
					Type:    plugin.FlagType_KeyValue,
					Default: "",
					Desc:    "Filter discovered resources by label, e.g., --filters labels=env=prod,team --filters exclude:labels=tier=dev",
				},
			},
		},
	},
}
