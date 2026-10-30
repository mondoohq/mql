// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := neonConn(runtime)

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
			connection.DiscoveryOrganizations,
			connection.DiscoveryProjects,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	conn := neonConn(runtime)
	conf := conn.Asset().Connections[0]

	wantOrgs := stringx.Contains(targets, connection.DiscoveryOrganizations)
	wantProjects := stringx.Contains(targets, connection.DiscoveryProjects)
	if !wantOrgs && !wantProjects {
		return nil, nil
	}

	root, err := getNeon(runtime)
	if err != nil {
		return nil, err
	}

	assetList := []*inventory.Asset{}

	if wantOrgs {
		// The organization list already honors the --organization flag, so
		// discovery emits assets for exactly the organizations a plain query
		// would see.
		organizations := root.GetOrganizations()
		if organizations.Error != nil {
			return nil, organizations.Error
		}
		for _, it := range organizations.Data {
			org, ok := it.(*mqlNeonOrganization)
			if !ok {
				continue
			}
			name := org.Name.Data
			if name == "" {
				name = org.Handle.Data
			}
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewNeonOrganizationIdentifier(org.Id.Data)},
				Name:        name,
				Platform:    connection.NewNeonOrganizationPlatform(org.Id.Data),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), org.Id.Data, "")},
			})
		}
	}

	if wantProjects {
		// The root collects projects per organization, because the list
		// endpoint rejects a request that does not name one, so discovery emits
		// assets for exactly the projects a plain query would see. A project
		// that belongs to no organization is not among them and is reached by
		// naming it instead, as neon.project(id: "...").
		projects := root.GetProjects()
		if projects.Error != nil {
			return nil, projects.Error
		}
		for _, it := range projects.Data {
			project, ok := it.(*mqlNeonProject)
			if !ok {
				continue
			}
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewNeonProjectIdentifier(project.Id.Data)},
				Name:        project.Name.Data,
				Platform:    connection.NewNeonProjectPlatform(project.cacheOrgID, project.Id.Data),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), project.cacheOrgID, project.Id.Data)},
			})
		}
	}

	return assetList, nil
}

// scopedConfig clones the parent connection config for a discovered child
// asset, stamping the organization (and optional project) it is scoped to.
func scopedConfig(conf *inventory.Config, parentID uint32, orgID, projectID string) *inventory.Config {
	child := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	options := map[string]string{}
	if orgID != "" {
		options["orgId"] = orgID
	}
	if org := conf.Options["organization"]; org != "" {
		options["organization"] = org
	}
	if projectID != "" {
		options["projectId"] = projectID
	}
	child.Options = options
	return child
}
