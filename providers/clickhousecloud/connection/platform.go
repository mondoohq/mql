// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// OptionOrg is the ClickHouse Cloud organization ID.
	OptionOrg = "organization-id"
	// OptionAPIURL overrides the ClickHouse Cloud API base URL.
	OptionAPIURL = "api-url"
)

var platformIdClickhousecloudOrg = "//platformid.api.mondoo.app/runtime/clickhousecloud/organization/"

// NewClickhousecloudOrgPlatform returns the platform for a ClickHouse Cloud organization.
func NewClickhousecloudOrgPlatform(orgID string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "clickhousecloud",
		Title:                 "ClickHouse Cloud",
		Family:                []string{"clickhousecloud"},
		Kind:                  "api",
		Runtime:               "clickhousecloud",
		TechnologyUrlSegments: []string{"saas", "clickhousecloud", "organization", orgID},
	}
}

// NewClickhousecloudOrgIdentifier returns the stable platform id for an organization.
func NewClickhousecloudOrgIdentifier(orgID string) string {
	return platformIdClickhousecloudOrg + orgID
}
