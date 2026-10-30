// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of every platform the GitLab provider can
// emit. Dynamic fields (TechnologyUrlSegments) are added by the platform
// builders.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "gitlab-group",
		Title:   "GitLab Group",
		Family:  []string{"gitlab"},
		Kind:    []string{"api"},
		Runtime: []string{"gitlab"},
	},
	{
		Name:    "gitlab-project",
		Title:   "GitLab Project",
		Family:  []string{"gitlab"},
		Kind:    []string{"api"},
		Runtime: []string{"gitlab"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog descriptor for the given platform name,
// or nil if it is not in the catalog.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
