// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "atlassian-scim",
		Title:   "Atlassian SCIM",
		Kind:    []string{"api"},
		Runtime: []string{"atlassian"},
	},
	{
		Name:    "atlassian-admin",
		Title:   "Atlassian Admin",
		Kind:    []string{"api"},
		Runtime: []string{"atlassian"},
	},
	{
		Name:    "atlassian-jira",
		Title:   "Atlassian Jira",
		Kind:    []string{"api"},
		Runtime: []string{"atlassian"},
	},
	{
		Name:    "atlassian-confluence",
		Title:   "Atlassian Confluence",
		Kind:    []string{"api"},
		Runtime: []string{"atlassian"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
