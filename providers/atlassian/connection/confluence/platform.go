// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package confluence

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func (a *ConfluenceConnection) PlatformInfo() *inventory.Platform {
	return GetPlatformForObject("atlassian-confluence")
}

func GetPlatformForObject(platformName string) *inventory.Platform {
	if platformName != "atlassian-confluence" && platformName != "" {
		return &inventory.Platform{
			Name:                  platformName,
			Title:                 "Atlassian Confluence",
			Kind:                  "api",
			Runtime:               "atlassian",
			TechnologyUrlSegments: []string{"saas", "atlassian", "confluence"},
		}
	}
	return &inventory.Platform{
		Name:                  "atlassian-confluence",
		Title:                 "Atlassian Confluence",
		Kind:                  "api",
		Runtime:               "atlassian",
		TechnologyUrlSegments: []string{"saas", "atlassian", "confluence"},
	}
}

func (a *ConfluenceConnection) PlatformID() string {
	hostname := strings.TrimPrefix(a.name, "https://")
	host := strings.Replace(hostname, ".", "-", -1)
	return "//platformid.api.mondoo.app/runtime/atlassian/confluence/" + host
}
