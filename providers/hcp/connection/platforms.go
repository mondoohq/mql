// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit. Every
// asset type produced by discovery has an entry here so the CLI and generated
// docs can list what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "hcp-organization",
		Title:   "HashiCorp Cloud Platform Organization",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
	{
		Name:    "hcp-project",
		Title:   "HashiCorp Cloud Platform Project",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
	{
		Name:    "hcp-vault-cluster",
		Title:   "HashiCorp Cloud Platform Vault Cluster",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
	{
		Name:    "hcp-consul-cluster",
		Title:   "HashiCorp Cloud Platform Consul Cluster",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
	{
		Name:    "hcp-boundary-cluster",
		Title:   "HashiCorp Cloud Platform Boundary Cluster",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
	{
		Name:    "hcp-packer-registry",
		Title:   "HashiCorp Cloud Platform Packer Registry",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
	{
		Name:    "hcp-waypoint-application",
		Title:   "HashiCorp Cloud Platform Waypoint Application",
		Family:  []string{"hcp"},
		Kind:    []string{"api"},
		Runtime: []string{"hcp"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
