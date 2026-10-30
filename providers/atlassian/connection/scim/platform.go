// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package scim

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func (a *ScimConnection) PlatformInfo() *inventory.Platform {
	return GetPlatformForObject("atlassian-scim")
}

func GetPlatformForObject(platformName string) *inventory.Platform {
	if platformName != "atlassian-scim" && platformName != "" {
		return &inventory.Platform{
			Name:                  platformName,
			Title:                 "Atlassian SCIM",
			Kind:                  "api",
			Runtime:               "atlassian",
			TechnologyUrlSegments: []string{"saas", "atlassian", "scim"},
		}
	}
	return &inventory.Platform{
		Name:                  "atlassian-scim",
		Title:                 "Atlassian SCIM",
		Kind:                  "api",
		Runtime:               "atlassian",
		TechnologyUrlSegments: []string{"saas", "atlassian", "scim"},
	}
}

func (a *ScimConnection) PlatformID() string {
	return "//platformid.api.mondoo.app/runtime/atlassian/scim/" + a.Directory()
}
