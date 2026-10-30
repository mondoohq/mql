// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hcp/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// scopedResourceIDs resolves the leaf resource id and its project id for a
// resource init, preferring an explicit id argument and otherwise reading the
// scope the discovered asset's connection carries.
func scopedResourceIDs(runtime *plugin.Runtime, args map[string]*llx.RawData) (resourceID, projectID string, err error) {
	if idRaw, ok := args["id"]; ok {
		resourceID, _ = idRaw.Value.(string)
	}
	conn := hcpConn(runtime)
	if resourceID == "" {
		resourceID = conn.ResourceID()
	}
	projectID = conn.ProjectID()
	return resourceID, projectID, nil
}

// Discover walks the organization (or the single scoped project) and emits a
// child asset for each project and product resource selected by the discovery
// targets.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := hcpConn(runtime)
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}

	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return in, nil
	}
	targets := conf.Discover.Targets
	want := func(t string) bool {
		return stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryAuto, t)
	}

	ctx := context.Background()
	oid, err := conn.EnsureOrgID(ctx)
	if err != nil {
		return nil, err
	}

	// Resolve the set of projects to walk. An organization-scoped connection
	// enumerates every project; a project-scoped one walks just its project.
	type projectRef struct{ id, name string }
	var projects []projectRef
	switch conn.Scope() {
	case connection.ScopeOrg:
		list, err := listMqlHcpProjects(runtime, oid)
		if err != nil {
			return nil, err
		}
		for _, p := range list {
			proj := p.(*mqlHcpProject)
			projects = append(projects, projectRef{id: proj.Id.Data, name: proj.Name.Data})
			if want(connection.DiscoveryProjects) {
				in.Spec.Assets = append(in.Spec.Assets,
					childAsset(conf, conn.ID(), oid, connection.ScopeProject, "HCP project "+proj.Name.Data, proj.Id.Data, ""))
			}
		}
	case connection.ScopeProject:
		projects = append(projects, projectRef{id: conn.ProjectID()})
	default:
		return in, nil
	}

	for _, proj := range projects {
		if want(connection.DiscoveryVaultClusters) {
			clusters, err := listMqlHcpVaultClusters(runtime, oid, proj.id)
			if err != nil {
				return nil, err
			}
			for _, c := range clusters {
				id := c.(*mqlHcpVaultCluster).Id.Data
				in.Spec.Assets = append(in.Spec.Assets,
					childAsset(conf, conn.ID(), oid, connection.ScopeVaultCluster, "HCP Vault cluster "+id, proj.id, id))
			}
		}
		if want(connection.DiscoveryConsulClusters) {
			clusters, err := listMqlHcpConsulClusters(runtime, oid, proj.id)
			if err != nil {
				return nil, err
			}
			for _, c := range clusters {
				id := c.(*mqlHcpConsulCluster).Id.Data
				in.Spec.Assets = append(in.Spec.Assets,
					childAsset(conf, conn.ID(), oid, connection.ScopeConsulCluster, "HCP Consul cluster "+id, proj.id, id))
			}
		}
		if want(connection.DiscoveryBoundaryClusters) {
			clusters, err := listMqlHcpBoundaryClusters(runtime, oid, proj.id)
			if err != nil {
				return nil, err
			}
			for _, c := range clusters {
				id := c.(*mqlHcpBoundaryCluster).Id.Data
				in.Spec.Assets = append(in.Spec.Assets,
					childAsset(conf, conn.ID(), oid, connection.ScopeBoundaryCluster, "HCP Boundary cluster "+id, proj.id, id))
			}
		}
		if want(connection.DiscoveryPackerRegistries) {
			mqlProj, err := fetchMqlHcpProject(runtime, proj.id)
			if err != nil {
				return nil, err
			}
			reg, err := mqlProj.packerRegistry()
			if err != nil {
				return nil, err
			}
			if reg != nil {
				in.Spec.Assets = append(in.Spec.Assets,
					childAsset(conf, conn.ID(), oid, connection.ScopePackerRegistry, "HCP Packer registry "+reg.Id.Data, mqlProj.Id.Data, reg.Id.Data))
			}
		}
		if want(connection.DiscoveryWaypointApplications) {
			apps, err := listMqlHcpWaypointApplications(runtime, oid, proj.id)
			if err != nil {
				return nil, err
			}
			for _, a := range apps {
				app := a.(*mqlHcpWaypointApplication)
				in.Spec.Assets = append(in.Spec.Assets,
					childAsset(conf, conn.ID(), oid, connection.ScopeWaypointApplication, "HCP Waypoint application "+app.Name.Data, proj.id, app.Id.Data))
			}
		}
	}

	return in, nil
}

// childAsset clones the connection config, scopes it to a discovered resource,
// and builds the corresponding inventory asset. The org id is carried on the
// clone so the scanned child asset resolves without re-listing organizations.
func childAsset(conf *inventory.Config, parentID uint32, orgID, scope, name, projectID, resourceID string) *inventory.Asset {
	c := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	if c.Options == nil {
		c.Options = map[string]string{}
	}
	c.Options[connection.OptionScope] = scope
	c.Options[connection.OptionOrgID] = orgID
	c.Options[connection.OptionProjectID] = projectID
	c.Options[connection.OptionResourceID] = resourceID

	var platform *inventory.Platform
	var platformID string
	switch scope {
	case connection.ScopeProject, connection.ScopePackerRegistry:
		platform = connection.NewPlatform(scope, projectID)
		platformID = connection.NewPlatformID(scope, projectID)
	default:
		platform = connection.NewPlatform(scope, projectID, resourceID)
		platformID = connection.NewPlatformID(scope, projectID, resourceID)
	}

	return &inventory.Asset{
		PlatformIds: []string{platformID},
		Name:        name,
		Platform:    platform,
		Labels:      map[string]string{},
		Connections: []*inventory.Config{c},
	}
}
