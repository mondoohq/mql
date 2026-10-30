// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package admin

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func (a *AdminConnection) PlatformInfo() *inventory.Platform {
	return GetPlatformForObject("atlassian-admin")
}

func GetPlatformForObject(platformName string) *inventory.Platform {
	if platformName != "atlassian-admin" && platformName != "" {
		return &inventory.Platform{
			Name:                  platformName,
			Title:                 "Atlassian Admin",
			Kind:                  "api",
			Runtime:               "atlassian",
			TechnologyUrlSegments: []string{"saas", "atlassian", "admin"},
		}
	}
	return &inventory.Platform{
		Name:                  "atlassian-admin",
		Title:                 "Atlassian Admin",
		Kind:                  "api",
		Runtime:               "atlassian",
		TechnologyUrlSegments: []string{"saas", "atlassian", "admin"},
	}
}

func (a *AdminConnection) PlatformID() string {
	return "//platformid.api.mondoo.app/runtime/atlassian/admin"
}
