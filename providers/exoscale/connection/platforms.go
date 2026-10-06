// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit. The
// build exports it into dist/exoscale.json so the CLI and generated docs can
// list what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "exoscale-organization", Title: "Exoscale Organization", Family: []string{"exoscale"}, Kind: []string{"api"}, Runtime: []string{"exoscale"}},
	{Name: "exoscale-compute-instance", Title: "Exoscale Compute Instance", Family: []string{"exoscale"}, Kind: []string{"api"}, Runtime: []string{"exoscale"}},
	{Name: "exoscale-security-group", Title: "Exoscale Security Group", Family: []string{"exoscale"}, Kind: []string{"api"}, Runtime: []string{"exoscale"}},
	{Name: "exoscale-sks-cluster", Title: "Exoscale SKS Cluster", Family: []string{"exoscale"}, Kind: []string{"api"}, Runtime: []string{"exoscale"}},
	{Name: "exoscale-nlb", Title: "Exoscale Network Load Balancer", Family: []string{"exoscale"}, Kind: []string{"api"}, Runtime: []string{"exoscale"}},
	{Name: "exoscale-dbaas-service", Title: "Exoscale DBaaS Service", Family: []string{"exoscale"}, Kind: []string{"api"}, Runtime: []string{"exoscale"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
