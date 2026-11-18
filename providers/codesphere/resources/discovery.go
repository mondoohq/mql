// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discoveryTargets expands auto and all. auto leaves organizations out: their
// only checks are on membership, and listing members needs organization admin
// rights most scan tokens do not have.
func discoveryTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) {
		return []string{connection.DiscoveryOrganizations, connection.DiscoveryResourceGroups, connection.DiscoveryWorkspaces}
	}
	if stringx.Contains(targets, connection.DiscoveryAuto) {
		return []string{connection.DiscoveryResourceGroups, connection.DiscoveryWorkspaces}
	}
	return targets
}

func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.CodesphereConnection)
	conf := conn.Asset().Connections[0]
	targets := discoveryTargets(conf.Discover.Targets)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	root, err := getRoot(runtime)
	if err != nil {
		return nil, err
	}
	host := conn.Host()

	if stringx.Contains(targets, connection.DiscoveryOrganizations) {
		orgs := root.GetOrganizations()
		if orgs.Error != nil {
			return nil, orgs.Error
		}
		for _, it := range orgs.Data {
			org := it.(*mqlCodesphereOrganization)
			in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
				PlatformIds: []string{connection.OrganizationID(host, org.Id.Data)},
				Name:        org.Name.Data,
				Platform:    connection.NewOrganizationPlatform(host, org.Id.Data),
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), connection.OptionScopeOrganization, org.Id.Data)},
			})
		}
	}

	wantRGs := stringx.Contains(targets, connection.DiscoveryResourceGroups)
	wantWorkspaces := stringx.Contains(targets, connection.DiscoveryWorkspaces)
	if !wantRGs && !wantWorkspaces {
		return in, nil
	}

	rgs := root.GetResourceGroups()
	if rgs.Error != nil {
		return nil, rgs.Error
	}
	for _, it := range rgs.Data {
		rg := it.(*mqlCodesphereResourceGroup)
		rgID := int(rg.Id.Data)
		if wantRGs {
			in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
				PlatformIds: []string{connection.ResourceGroupID(host, rgID)},
				Name:        rg.Name.Data,
				Platform:    connection.NewResourceGroupPlatform(host, rgID),
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), connection.OptionScopeResourceGroup, strconv.Itoa(rgID))},
			})
		}
		if !wantWorkspaces {
			continue
		}
		list := rg.GetWorkspaces()
		if list.Error != nil {
			// A resource group whose workspaces are refused still yields the
			// others (ADR 046 §8).
			continue
		}
		for _, wit := range list.Data {
			ws := wit.(*mqlCodesphereWorkspace)
			wsID := int(ws.Id.Data)
			in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
				PlatformIds: []string{connection.WorkspaceID(host, wsID)},
				Name:        rg.Name.Data + "/" + ws.Name.Data,
				Platform:    connection.NewWorkspacePlatform(host, rgID, wsID),
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), connection.OptionScopeWorkspace, strconv.Itoa(wsID))},
			})
		}
	}
	return in, nil
}

// scopedConfig clones the installation's connection for a discovered child
// asset, keeping the API URL and pinning the child to one object.
func scopedConfig(conf *inventory.Config, parentID uint32, key, value string) *inventory.Config {
	child := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	options := map[string]string{key: value}
	if v := conf.Options[connection.OptionAPIURL]; v != "" {
		options[connection.OptionAPIURL] = v
	}
	child.Options = options
	return child
}
