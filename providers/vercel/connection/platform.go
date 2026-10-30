// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	DiscoveryAll      = "all"
	DiscoveryAuto     = "auto"
	DiscoveryTeams    = "teams"
	DiscoveryProjects = "projects"
)

const (
	PlatformIdVercelTeam    = "//platformid.api.mondoo.app/runtime/vercel/team/"
	PlatformIdVercelProject = "//platformid.api.mondoo.app/runtime/vercel/project/"
)

func NewVercelTeamPlatform(teamID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "vercel", "team", teamID},
	}
	PlatformByName("vercel-team").Apply(pf)
	return pf
}

func NewVercelProjectPlatform(teamID, projectID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "vercel", "team", teamID, "project", projectID},
	}
	PlatformByName("vercel-project").Apply(pf)
	return pf
}

func NewVercelTeamIdentifier(teamID string) string {
	return PlatformIdVercelTeam + teamID
}

func NewVercelProjectIdentifier(projectID string) string {
	return PlatformIdVercelProject + projectID
}
