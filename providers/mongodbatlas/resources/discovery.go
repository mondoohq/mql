// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mongodbatlas/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover enumerates the organization's projects and emits each as a child
// asset scoped to that project.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.MongoDBAtlasConnection)
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}

	conf := conn.Asset().Connections[0]
	if conf.Discover == nil ||
		!stringx.ContainsAnyOf(conf.Discover.Targets, connection.DiscoveryAll, connection.DiscoveryAuto, connection.DiscoveryProjects) {
		return in, nil
	}

	client := conn.Client()
	ctx := context.Background()

	for page := 1; ; page++ {
		resp, _, err := client.ProjectsAPI.ListGroups(ctx).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return in, err
		}
		results := resp.GetResults()
		for i := range results {
			p := results[i]
			projectID := p.GetId()

			// Clone preserves the credentials and options; we then scope the child
			// to a single project.
			c := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
			if c.Options == nil {
				c.Options = map[string]string{}
			}
			c.Options[connection.OptionPlane] = connection.PlaneProject
			c.Options[connection.OptionProjectID] = projectID
			c.Options[connection.OptionOrgID] = p.GetOrgId()

			asset := &inventory.Asset{
				PlatformIds: []string{connection.NewMongoDBAtlasProjectIdentifier(projectID)},
				Name:        p.GetName(),
				Platform:    connection.NewMongoDBAtlasProjectPlatform(projectID),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{c},
			}
			in.Spec.Assets = append(in.Spec.Assets, asset)
		}
		if len(results) < pageSize {
			break
		}
	}

	return in, nil
}
