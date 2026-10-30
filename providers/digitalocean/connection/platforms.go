// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "digitalocean",
		Title:   "DigitalOcean",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
	{
		Name:    "digitalocean-database",
		Title:   "DigitalOcean Database",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
	{
		Name:    "digitalocean-kubernetes-cluster",
		Title:   "DigitalOcean Kubernetes Cluster",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
	{
		Name:    "digitalocean-loadbalancer",
		Title:   "DigitalOcean Load Balancer",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
	{
		Name:    "digitalocean-firewall",
		Title:   "DigitalOcean Cloud Firewall",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
	{
		Name:    "digitalocean-spaces-bucket",
		Title:   "DigitalOcean Spaces Bucket",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
	{
		Name:    "digitalocean-gradientai-agent",
		Title:   "DigitalOcean GradientAI Agent",
		Family:  []string{"digitalocean"},
		Kind:    []string{"api"},
		Runtime: []string{"digitalocean"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
