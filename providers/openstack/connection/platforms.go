// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "openstack-project",
		Title:   "OpenStack Project",
		Family:  []string{"openstack"},
		Kind:    []string{"api"},
		Runtime: []string{"openstack"},
	},
	{
		Name:    "openstack-domain",
		Title:   "OpenStack Domain",
		Family:  []string{"openstack"},
		Kind:    []string{"api"},
		Runtime: []string{"openstack"},
	},
	{
		Name:    "openstack-system",
		Title:   "OpenStack System Scope",
		Family:  []string{"openstack"},
		Kind:    []string{"api"},
		Runtime: []string{"openstack"},
	},
	{
		Name:    "openstack-security-group",
		Title:   "OpenStack Security Group",
		Family:  []string{"openstack"},
		Kind:    []string{"api"},
		Runtime: []string{"openstack"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
