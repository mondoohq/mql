// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.VercelConnection)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conn.Asset().Connections[0].Discover.Targets)
	list, err := discover(runtime, targets)
	if err != nil {
		return in, err
	}

	in.Spec.Assets = list
	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryTeams,
			connection.DiscoveryProjects,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	conn := runtime.Connection.(*connection.VercelConnection)
	conf := conn.Asset().Connections[0]

	wantTeams := stringx.Contains(targets, connection.DiscoveryTeams)
	wantProjects := stringx.Contains(targets, connection.DiscoveryProjects)
	if !wantTeams && !wantProjects {
		return nil, nil
	}

	v, err := getMqlVercel(runtime)
	if err != nil {
		return nil, err
	}

	teams, err := v.teams()
	if err != nil {
		return nil, err
	}

	assetList := []*inventory.Asset{}
	for _, it := range teams {
		team := it.(*mqlVercelTeam)
		teamID := team.Id.Data
		teamName := team.Name.Data
		if teamName == "" {
			teamName = team.Slug.Data
		}

		if wantTeams {
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewVercelTeamIdentifier(teamID)},
				Name:        teamName,
				Platform:    connection.NewVercelTeamPlatform(teamID),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), teamID, "")},
			})
		}

		if wantProjects {
			projects := team.GetProjects()
			if projects.Error != nil {
				return nil, projects.Error
			}
			for _, pit := range projects.Data {
				project := pit.(*mqlVercelProject)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{connection.NewVercelProjectIdentifier(project.Id.Data)},
					Name:        project.Name.Data,
					Platform:    connection.NewVercelProjectPlatform(teamID, project.Id.Data),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), teamID, project.Id.Data)},
				})
			}
		}
	}

	return assetList, nil
}

// scopedConfig clones the parent connection config for a discovered child asset,
// stamping the team (and optional project) it is scoped to.
func scopedConfig(conf *inventory.Config, parentID uint32, teamID, projectID string) *inventory.Config {
	child := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	options := map[string]string{"teamId": teamID}
	if projectID != "" {
		options["projectId"] = projectID
	}
	child.Options = options
	return child
}

func getMqlVercel(runtime *plugin.Runtime) (*mqlVercel, error) {
	res, err := CreateResource(runtime, "vercel", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVercel), nil
}
