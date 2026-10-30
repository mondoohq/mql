// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/claude/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.ClaudeConnection)

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
			connection.DiscoveryOrg,
			connection.DiscoveryWorkspaces,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	conn := runtime.Connection.(*connection.ClaudeConnection)
	conf := conn.Asset().Connections[0]
	var assetList []*inventory.Asset

	orgID := conn.OrgID()
	if orgID == "" {
		return assetList, nil
	}

	for _, target := range targets {
		switch target {
		case connection.DiscoveryOrg:
			asset := &inventory.Asset{
				PlatformIds: []string{connection.NewClaudeOrgIdentifier(orgID)},
				Name:        "Claude Organization " + conn.OrgName(),
				Platform:    connection.NewClaudeOrgPlatform(orgID),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))},
			}
			assetList = append(assetList, asset)

		case connection.DiscoveryWorkspaces:
			res, err := CreateResource(runtime, "claude.organization", map[string]*llx.RawData{})
			if err != nil {
				return nil, err
			}
			org := res.(*mqlClaudeOrganization)
			workspaces, err := org.workspaces()
			if err != nil {
				return nil, err
			}

			for _, iws := range workspaces {
				ws := iws.(*mqlClaudeOrganizationWorkspace)
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewClaudeWorkspaceIdentifier(ws.Id.Data)},
					Name:        "Claude Workspace " + ws.Name.Data,
					Platform:    connection.NewClaudeWorkspacePlatform(orgID, ws.Id.Data),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))},
				}
				assetList = append(assetList, asset)
			}
		}
	}

	return assetList, nil
}
