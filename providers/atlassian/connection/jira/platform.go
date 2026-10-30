// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jira

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func (a *JiraConnection) PlatformInfo() *inventory.Platform {
	return GetPlatformForObject("atlassian-jira")
}

func GetPlatformForObject(platformName string) *inventory.Platform {
	if platformName != "atlassian-jira" && platformName != "" {
		return &inventory.Platform{
			Name:                  platformName,
			Title:                 "Atlassian Jira",
			Kind:                  "api",
			Runtime:               "atlassian",
			TechnologyUrlSegments: []string{"saas", "atlassian", "jira"},
		}
	}
	return &inventory.Platform{
		Name:                  "atlassian-jira",
		Title:                 "Atlassian Jira",
		Kind:                  "api",
		Runtime:               "atlassian",
		TechnologyUrlSegments: []string{"saas", "atlassian", "jira"},
	}
}

func (a *JiraConnection) PlatformID() string {
	hostname := strings.TrimPrefix(a.name, "https://")
	host := strings.Replace(hostname, ".", "-", -1)
	return "//platformid.api.mondoo.app/runtime/atlassian/jira/" + host
}
