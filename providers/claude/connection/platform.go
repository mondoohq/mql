// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/inventory"

const (
	DiscoveryAll        = "all"
	DiscoveryAuto       = "auto"
	DiscoveryOrg        = "organization"
	DiscoveryWorkspaces = "workspaces"
)

var (
	PlatformIdOrg       = "//platformid.api.mondoo.app/runtime/claude/organization/"
	PlatformIdWorkspace = "//platformid.api.mondoo.app/runtime/claude/workspace/"
)

func NewClaudeOrgPlatform(orgID string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"ai", "claude", "organization", orgID},
	}
	PlatformByName("claude-organization").Apply(p)
	return p
}

func NewClaudeWorkspacePlatform(orgID, workspaceID string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"ai", "claude", "organization", orgID, "workspace", workspaceID},
	}
	PlatformByName("claude-workspace").Apply(p)
	return p
}

func NewClaudeAPIPlatform(host string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"ai", "claude", host},
	}
	PlatformByName("claude").Apply(p)
	return p
}

func NewClaudeOrgIdentifier(orgID string) string {
	return PlatformIdOrg + orgID
}

func NewClaudeWorkspaceIdentifier(workspaceID string) string {
	return PlatformIdWorkspace + workspaceID
}
